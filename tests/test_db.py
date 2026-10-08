from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, inspect, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.bootstrap import bootstrap
from app.core.config import Settings, get_settings
from app.core.keys import KeyEncryptionError, decrypt_private_key, rotate_key
from app.core.security_utils import hash_api_key
from app.db.models import ClientModel, SigningKeyModel
from tests.conftest import FULL_KEY, app

FULL = {"X-API-Key": FULL_KEY}


def test_bootstrap_runs_migrations_and_is_idempotent(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path / 'boot.db'}"
    settings = Settings(DATABASE_URL=url, APP_MASTER_KEY=Fernet.generate_key().decode())
    bootstrap(settings)
    bootstrap(settings)  # segunda vez não pode criar outra chave nem falhar

    engine = create_engine(url)
    assert {"clients", "signing_keys", "alembic_version"} <= set(inspect(engine).get_table_names())
    with Session(engine) as session:
        keys = session.scalars(select(SigningKeyModel)).all()
    assert len(keys) == 1 and keys[0].active


def test_only_one_active_key(client):
    with Session(app.state.engine) as session:
        session.add(SigningKeyModel(kid="outra", private_key_encrypted="x", active=True))
        with pytest.raises(IntegrityError):
            session.commit()


def test_rotation_keeps_old_tokens_valid_until_they_expire(client):
    old = client.post("/api/v1/auth/login", json={"username": "maria.silva", "password": "S3nha!"}, headers=FULL)
    old_token = old.json()["access_token"]

    with Session(app.state.engine) as session:
        rotate_key(session, get_settings().APP_MASTER_KEY)
        session.commit()
    app.state.tokens._loaded_at = 0  # simula o fim do cache de 30s

    new_token = client.post(
        "/api/v1/auth/login", json={"username": "maria.silva", "password": "S3nha!"}, headers=FULL
    ).json()["access_token"]
    assert jwt.get_unverified_header(new_token)["kid"] != jwt.get_unverified_header(old_token)["kid"]
    assert len(client.get("/.well-known/jwks.json").json()["keys"]) == 2

    introspect = lambda t: client.post("/api/v1/auth/introspect", json={"token": t}, headers=FULL).json()  # noqa: E731
    assert introspect(old_token)["active"] is True
    assert introspect(new_token)["active"] is True

    # Passado o tempo de vida dos tokens, a chave aposentada sai do JWKS e o token antigo deixa de valer
    with Session(app.state.engine) as session:
        session.execute(
            update(SigningKeyModel)
            .where(SigningKeyModel.active.is_(False))
            .values(retired_at=datetime.now(timezone.utc) - timedelta(days=2))
        )
        session.commit()
    app.state.tokens._loaded_at = 0
    assert introspect(old_token)["active"] is False
    assert len(client.get("/.well-known/jwks.json").json()["keys"]) == 1


def test_new_client_works_immediately(client):
    with Session(app.state.engine) as session:
        session.add(
            ClientModel(
                client_id="nova",
                api_key_sha256=hash_api_key("chave-nova"),
                access_level="basic",
                group_prefixes=[],
                required_groups=[],
            )
        )
        session.commit()
    r = client.post(
        "/api/v1/auth/basic/login",
        json={"username": "maria.silva", "password": "S3nha!"},
        headers={"X-API-Key": "chave-nova"},
    )
    assert r.status_code == 200


def test_wrong_master_key_is_reported(client):
    with Session(app.state.engine) as session:
        row = session.scalar(select(SigningKeyModel).where(SigningKeyModel.active.is_(True)))
    with pytest.raises(KeyEncryptionError, match="APP_MASTER_KEY"):
        decrypt_private_key(row, Fernet.generate_key().decode())


def test_ready_reports_database(client):
    r = client.get("/health/ready").json()
    assert r["database"] == "ok"


def test_cli_discards_broken_terminal_bytes():
    from app.cli import clean

    # "informa" + "ç" + byte solto (meio "ã" apagado com Backspace) + "ã" + "o", como o Python lê do terminal
    broken = b"informa\xc3\xa7\xc3\xc3\xa3o".decode("utf-8", "surrogateescape")
    assert clean(broken) == "informação"
    assert clean(broken).encode("utf-8")  # não pode mais quebrar ao gravar no banco
    assert clean("informação") == "informação"  # acentos combinados viram a forma composta
