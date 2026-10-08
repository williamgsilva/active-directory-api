from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.ad.client import ActiveDirectory
from app.core.clients import ClientApp, ClientStore
from app.core.tokens import TokenService

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="API key da aplicação cliente")


def get_ad(request: Request) -> ActiveDirectory:
    return request.app.state.ad


def get_tokens(request: Request) -> TokenService:
    return request.app.state.tokens


def get_registry(request: Request) -> ClientStore:
    return request.app.state.clients


def require_client(
    api_key: Annotated[str | None, Security(_api_key_header)],
    registry: Annotated[ClientStore, Depends(get_registry)],
) -> ClientApp:
    client = registry.authenticate(api_key)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key ausente ou inválida",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return client


def require_full_client(client: Annotated[ClientApp, Depends(require_client)]) -> ClientApp:
    if not client.is_full:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Aplicação com acesso básico: use os endpoints /api/v1/auth/basic/*",
        )
    return client


def require_directory_client(client: Annotated[ClientApp, Depends(require_full_client)]) -> ClientApp:
    if not client.allow_directory_lookup:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Aplicação sem permissão para consultar o diretório")
    return client


AD = Annotated[ActiveDirectory, Depends(get_ad)]
Tokens = Annotated[TokenService, Depends(get_tokens)]
Client = Annotated[ClientApp, Depends(require_client)]
FullClient = Annotated[ClientApp, Depends(require_full_client)]
DirectoryClient = Annotated[ClientApp, Depends(require_directory_client)]
