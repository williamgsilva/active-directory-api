import pytest
from ldap3 import MOCK_SYNC, Connection, Server

from app.ad.client import ActiveDirectory, InvalidCredentialsError
from app.core.config import Settings

BASE = "DC=example,DC=local"


def add_user(conn, sam, mail=None, upn=None):
    attrs = {"objectClass": ["user"], "objectCategory": "person", "sAMAccountName": sam}
    if mail:
        attrs["mail"] = mail
    if upn:
        attrs["userPrincipalName"] = upn
    conn.strategy.add_entry(f"CN={sam},OU=Users,{BASE}", attrs)


@pytest.fixture
def ad_conn():
    conn = Connection(Server("mock"), user="cn=admin", password="p", client_strategy=MOCK_SYNC)
    add_user(conn, "ana.costa", mail="ana.costa@example.com", upn="ana.costa@example.local")
    add_user(conn, "wsouza", mail="w.souza@outrodominio.com")
    add_user(conn, "dup1", mail="compartilhado@example.com")
    add_user(conn, "dup2", mail="compartilhado@example.com")
    conn.bind()
    return ActiveDirectory(Settings(AD_BASE_DOMAIN=BASE, AD_DOMAIN="example.local")), conn


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("ana.costa", "ana.costa"),
        ("EXAMPLE\\ana.costa", "ana.costa"),
        ("ana.costa@example.com", "ana.costa"),  # e-mail (atributo mail)
        ("w.souza@outrodominio.com", "wsouza"),  # qualquer domínio cadastrado no AD
        ("ana.costa@example.local", "ana.costa"),  # UPN
        ("semmail@example.local", "semmail"),  # fallback: usuario@AD_DOMAIN
    ],
)
def test_resolve_username(ad_conn, identifier, expected):
    ad, conn = ad_conn
    assert ad._resolve_username(conn, identifier) == expected


@pytest.mark.parametrize(
    "identifier",
    [
        "naoexiste@example.com",  # e-mail que não está no AD
        "compartilhado@example.com",  # e-mail em mais de um usuário: ambíguo
        "*@example.com",  # tentativa de wildcard / injection
        "a)(mail=*@example.com",
    ],
)
def test_resolve_username_rejects(ad_conn, identifier):
    ad, conn = ad_conn
    with pytest.raises(InvalidCredentialsError):
        ad._resolve_username(conn, identifier)
