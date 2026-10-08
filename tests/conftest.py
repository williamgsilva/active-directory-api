import os

import pytest
from fastapi.testclient import TestClient

from cryptography.fernet import Fernet  # noqa: E402

# Banco em memória e chave mestra só para os testes (sobrepõem o config/app.env)
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["APP_MASTER_KEY"] = Fernet.generate_key().decode()

from app.ad.client import ADUser, InvalidCredentialsError, normalize_username  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.keys import ensure_active_key  # noqa: E402
from app.db.models import Base, ClientModel  # noqa: E402
from app.core.security_utils import hash_api_key, hash_password  # noqa: E402
from app.main import app  # noqa: E402

FULL_KEY = "chave-deploy"
PORTAL_KEY = "chave-portal"
FULL_DOCS = ("docs-deploy", "senha-docs-deploy")
PORTAL_DOCS = ("docs-portal", "senha-docs-portal")


class FakeAD:
    users = {
        "maria.silva": (
            "S3nha!",
            ADUser(
                username="maria.silva",
                first_name="Maria",
                last_name="Silva",
                email="maria.silva@example.com",
                groups=["GRP_APP_ADMIN", "GRP_APP_SETUP", "GRP_VPN", "Domain Users"],
            ),
        ),
        "joao.souza": (
            "0utra!",
            ADUser(username="joao.souza", first_name="João", last_name="Souza", email="joao@example.com", groups=["Domain Users"]),
        ),
    }

    def _resolve(self, identifier):
        if "@" in identifier:
            for login, (_, user) in self.users.items():
                if user.email == identifier:
                    return login
            raise InvalidCredentialsError("Usuário ou senha inválidos")
        return normalize_username(identifier)

    def authenticate(self, username, password):
        username = self._resolve(username)
        stored = self.users.get(username)
        if not stored or not password or stored[0] != password:
            raise InvalidCredentialsError("Usuário ou senha inválidos")
        return stored[1]

    def get_user(self, username):
        try:
            stored = self.users.get(self._resolve(username))
        except InvalidCredentialsError:
            return None
        return stored[1] if stored else None

    def get_group_members(self, group):
        members = [u for u, (_, user) in self.users.items() if group in user.groups]
        return members or None

    def ping(self):
        pass


@pytest.fixture
def client():
    with TestClient(app) as c:
        app.state.ad = FakeAD()
        engine = app.state.engine
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            ensure_active_key(session, get_settings().APP_MASTER_KEY)
            session.add_all(
                [
                    ClientModel(
                        client_id="deploy-app",
                        api_key_sha256=hash_api_key(FULL_KEY),
                        access_level="full",
                        group_prefixes=["GRP_APP_"],
                        required_groups=[],
                        allow_directory_lookup=True,
                        docs_username=FULL_DOCS[0],
                        docs_password_hash=hash_password(FULL_DOCS[1]),
                    ),
                    ClientModel(
                        client_id="portal",
                        api_key_sha256=hash_api_key(PORTAL_KEY),
                        access_level="basic",
                        group_prefixes=[],
                        required_groups=["GRP_VPN"],
                        docs_username=PORTAL_DOCS[0],
                        docs_password_hash=hash_password(PORTAL_DOCS[1]),
                    ),
                ]
            )
            session.commit()
        yield c
