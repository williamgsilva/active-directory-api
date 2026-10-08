import jwt
import pytest

from app.ad.client import InvalidCredentialsError, normalize_username
from app.core.config import get_settings
from tests.conftest import FULL_DOCS, FULL_KEY, PORTAL_DOCS, PORTAL_KEY

FULL = {"X-API-Key": FULL_KEY}
PORTAL = {"X-API-Key": PORTAL_KEY}


def login(client, headers, username="maria.silva", password="S3nha!"):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password}, headers=headers)


def basic_login(client, headers, username="maria.silva", password="S3nha!"):
    return client.post("/api/v1/auth/basic/login", json={"username": username, "password": password}, headers=headers)


def test_login_requires_api_key(client):
    assert login(client, {}).status_code == 401
    assert login(client, {"X-API-Key": "errada"}).status_code == 401


def test_login_invalid_password(client):
    r = login(client, FULL, password="errada")
    assert r.status_code == 401
    assert r.json()["detail"] == "Usuário ou senha inválidos"


def test_login_ok_filters_groups_by_client_prefix(client):
    r = login(client, FULL, username="EXAMPLE\\maria.silva")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["groups"] == ["GRP_APP_ADMIN", "GRP_APP_SETUP"]

    jwks = client.get("/.well-known/jwks.json").json()
    key = jwt.PyJWK(jwks["keys"][0])
    claims = jwt.decode(body["access_token"], key, algorithms=["RS256"], audience="deploy-app", issuer=get_settings().JWT_ISSUER)
    assert claims["sub"] == "maria.silva"
    assert claims["groups"] == body["user"]["groups"]


def test_login_required_groups(client):
    assert basic_login(client, PORTAL).status_code == 200
    assert basic_login(client, PORTAL, username="joao.souza", password="0utra!").status_code == 403


def test_introspect_checks_audience(client):
    token = login(client, FULL).json()["access_token"]
    r = client.post("/api/v1/auth/introspect", json={"token": token}, headers=FULL)
    assert r.json()["active"] is True

    # Token emitido para o FULL não vale para o portal
    r = client.post("/api/v1/auth/basic/introspect", json={"token": token}, headers=PORTAL)
    assert r.json()["active"] is False


def test_authorize_any_and_all(client):
    token = login(client, FULL).json()["access_token"]
    body = {"token": token, "groups": ["GRP_APP_ADMIN", "GRP_APP_REDIS"]}

    r = client.post("/api/v1/auth/authorize", json=body, headers=FULL).json()
    assert r["authorized"] is True
    assert r["missing_groups"] == ["GRP_APP_REDIS"]

    r = client.post("/api/v1/auth/authorize", json={**body, "mode": "all"}, headers=FULL).json()
    assert r["authorized"] is False


def test_authorize_rejects_bad_token(client):
    r = client.post("/api/v1/auth/authorize", json={"token": "x.y.z", "groups": ["A"]}, headers=FULL)
    assert r.status_code == 401


def test_directory_lookup_permissions(client):
    assert client.get("/api/v1/users/maria.silva", headers=PORTAL).status_code == 403
    r = client.get("/api/v1/users/maria.silva", headers=FULL)
    assert r.status_code == 200
    assert "GRP_VPN" not in r.json()["groups"]
    assert client.get("/api/v1/users/maria.silva@example.com", headers=FULL).json()["username"] == "maria.silva"
    assert client.get("/api/v1/users/ninguem", headers=FULL).status_code == 404


# ------------------------------------------------------------------ nível básico


def test_basic_login_returns_only_minimal_fields(client):
    r = basic_login(client, PORTAL)
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == {"login": "maria.silva", "email": "maria.silva@example.com", "is_active": True}

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "maria.silva"
    assert claims["access_level"] == "basic"
    assert not {"groups", "name", "upn"} & claims.keys()


def test_basic_introspect(client):
    token = basic_login(client, PORTAL).json()["access_token"]
    r = client.post("/api/v1/auth/basic/introspect", json={"token": token}, headers=PORTAL).json()
    assert r["active"] is True
    assert r["login"] == "maria.silva"
    assert "claims" not in r


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", "/api/v1/auth/login", {"username": "maria.silva", "password": "S3nha!"}),
        ("post", "/api/v1/auth/introspect", {"token": "x"}),
        ("post", "/api/v1/auth/authorize", {"token": "x", "groups": ["A"]}),
        ("get", "/api/v1/users/maria.silva", None),
        ("get", "/api/v1/groups/GRP_VPN/members", None),
    ],
)
def test_basic_client_blocked_on_full_endpoints(client, method, path, body):
    r = client.request(method, path, json=body, headers=PORTAL)
    assert r.status_code == 403


def test_full_client_can_use_basic_endpoints(client):
    assert basic_login(client, FULL).status_code == 200


# ------------------------------------------------------------------ login por e-mail


def test_login_by_email(client):
    r = basic_login(client, PORTAL, username="maria.silva@example.com")
    assert r.status_code == 200
    assert r.json()["user"]["login"] == "maria.silva"
    assert basic_login(client, PORTAL, username="naoexiste@example.com").status_code == 401


# ------------------------------------------------------------------ documentação


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_require_credentials(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, auth=(FULL_DOCS[0], "errada")).status_code == 401
    assert client.get(path, auth=FULL_DOCS).status_code == 200


def test_docs_api_key_is_not_enough(client):
    assert client.get("/docs", headers=FULL).status_code == 401


def test_openapi_hides_full_endpoints_for_basic_client(client):
    full = client.get("/openapi.json", auth=FULL_DOCS).json()["paths"]
    basic = client.get("/openapi.json", auth=PORTAL_DOCS).json()["paths"]
    assert "/api/v1/auth/login" in full and "/api/v1/users/{username}" in full
    assert "/api/v1/auth/login" not in basic and "/api/v1/users/{username}" not in basic
    assert "/api/v1/auth/basic/login" in basic and "/health" in basic


def test_group_members_scope(client):
    r = client.get("/api/v1/groups/GRP_APP_SETUP/members", headers=FULL)
    assert r.json()["members"] == ["maria.silva"]
    assert client.get("/api/v1/groups/Domain Users/members", headers=FULL).status_code == 403


@pytest.mark.parametrize("raw", ["maria", "maria@example.local", "EXAMPLE\\maria", "  maria  "])
def test_normalize_username(raw):
    assert normalize_username(raw) == "maria"


@pytest.mark.parametrize("raw", ["", "*", "a)(cn=*", "a b", "x" * 65])
def test_normalize_username_rejects(raw):
    with pytest.raises(InvalidCredentialsError):
        normalize_username(raw)
