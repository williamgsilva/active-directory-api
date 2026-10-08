import logging
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, HTTPException, status

from app.ad.client import ADUnavailableError, ADUser, InvalidCredentialsError
from app.api import tags
from app.api.deps import AD, Client, FullClient, Tokens
from app.api.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    BasicIntrospectResponse,
    BasicLoginResponse,
    BasicUserInfo,
    IntrospectResponse,
    LoginRequest,
    LoginResponse,
    TokenRequest,
    UserInfo,
)
from app.core.clients import ClientApp
from app.core.tokens import TokenService

logger = logging.getLogger(__name__)

# Endpoints completos: só aplicações com access_level=full
router = APIRouter(prefix="/auth", tags=[tags.FULL_AUTH])
# Endpoints básicos: qualquer aplicação; devolvem só login, e-mail e status
basic_router = APIRouter(prefix="/auth/basic", tags=[tags.BASIC_AUTH])


def to_user_info(user: ADUser, client: ClientApp) -> UserInfo:
    days = None
    if user.password_expires_at:
        days = (user.password_expires_at - datetime.now(timezone.utc)).days
    return UserInfo(
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        display_name=user.display_name,
        user_principal_name=user.user_principal_name,
        email=user.email,
        last_password_change=user.last_password_change,
        password_expires_at=user.password_expires_at,
        password_never_expires=user.password_never_expires,
        password_expires_in_days=days,
        last_logon=user.last_logon,
        is_active=user.is_active,
        groups=client.filter_groups(user.groups),
    )


def ad_unavailable(e: ADUnavailableError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))


def authenticate_user(body: LoginRequest, client: ClientApp, ad) -> ADUser:
    try:
        user = ad.authenticate(body.username, body.password)
    except InvalidCredentialsError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos")
    except ADUnavailableError as e:
        raise ad_unavailable(e)

    if not client.is_allowed(user.groups):
        logger.warning(f"[{client.client_id}] '{user.username}' autenticou mas não pertence aos grupos exigidos")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuário sem permissão para acessar esta aplicação")
    return user


def decode_or_none(tokens: TokenService, token: str, client: ClientApp) -> tuple[dict | None, str | None]:
    try:
        return tokens.decode(token, audience=client.client_id), None
    except jwt.PyJWTError as e:
        return None, str(e)


# ---------------------------------------------------------------- nível completo

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Autentica usuário no AD e emite um JWT",
    responses={401: {"description": "Credenciais inválidas"}, 403: {"description": "Usuário sem acesso à aplicação"}},
)
def login(body: LoginRequest, client: FullClient, ad: AD, tokens: Tokens):
    user = authenticate_user(body, client, ad)
    info = to_user_info(user, client)
    token, expires_in = tokens.issue(
        subject=user.username,
        audience=client.client_id,
        claims={
            "name": user.display_name or " ".join(filter(None, [user.first_name, user.last_name])) or None,
            "email": user.email,
            "upn": user.user_principal_name,
            "groups": info.groups,
            "access_level": "full",
        },
    )
    logger.info(f"[{client.client_id}] Login realizado com sucesso para '{user.username}'")
    return LoginResponse(access_token=token, expires_in=expires_in, user=info)


@router.post("/introspect", response_model=IntrospectResponse, summary="Valida um JWT emitido para a aplicação")
def introspect(body: TokenRequest, client: FullClient, tokens: Tokens):
    claims, error = decode_or_none(tokens, body.token, client)
    if claims is None:
        return IntrospectResponse(active=False, error=error)
    return IntrospectResponse(active=True, claims=claims)


@router.post(
    "/authorize",
    response_model=AuthorizeResponse,
    summary="Verifica se o dono do token pertence aos grupos informados",
    description=(
        "Com `mode=any` basta pertencer a um dos grupos; com `mode=all`, a todos. "
        "A checagem usa os grupos gravados no token, portanto só enxerga grupos dentro dos "
        "`group_prefixes` configurados para a aplicação."
    ),
)
def authorize(body: AuthorizeRequest, client: FullClient, tokens: Tokens):
    try:
        claims = tokens.decode(body.token, audience=client.client_id)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido: {e}")

    user_groups = {g.upper() for g in claims.get("groups", [])}
    matched = [g for g in body.groups if g.upper() in user_groups]
    missing = [g for g in body.groups if g.upper() not in user_groups]
    authorized = bool(matched) if body.mode == "any" else not missing
    return AuthorizeResponse(authorized=authorized, username=claims["sub"], matched_groups=matched, missing_groups=missing)


# ---------------------------------------------------------------- nível básico

@basic_router.post(
    "/login",
    response_model=BasicLoginResponse,
    summary="Autentica usuário no AD e devolve só login, e-mail e status",
    description=(
        "Aceita o login do AD ou o e-mail cadastrado no AD. O token emitido também carrega apenas "
        "login (`sub`) e e-mail. Os `required_groups` da aplicação continuam sendo exigidos."
    ),
    responses={401: {"description": "Credenciais inválidas"}, 403: {"description": "Usuário sem acesso à aplicação"}},
)
def basic_login(body: LoginRequest, client: Client, ad: AD, tokens: Tokens):
    user = authenticate_user(body, client, ad)
    token, expires_in = tokens.issue(
        subject=user.username,
        audience=client.client_id,
        claims={"email": user.email, "access_level": "basic"},
    )
    logger.info(f"[{client.client_id}] Login (básico) realizado com sucesso para '{user.username}'")
    return BasicLoginResponse(
        access_token=token,
        expires_in=expires_in,
        user=BasicUserInfo(login=user.username, email=user.email, is_active=user.is_active),
    )


@basic_router.post("/introspect", response_model=BasicIntrospectResponse, summary="Valida um JWT (resposta resumida)")
def basic_introspect(body: TokenRequest, client: Client, tokens: Tokens):
    claims, error = decode_or_none(tokens, body.token, client)
    if claims is None:
        return BasicIntrospectResponse(active=False, error=error)
    return BasicIntrospectResponse(
        active=True,
        login=claims["sub"],
        email=claims.get("email"),
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
    )
