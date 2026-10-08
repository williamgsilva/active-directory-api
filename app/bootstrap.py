"""
Prepara o banco antes da API subir: aplica as migrations e cria a primeira chave JWT se não houver.

Roda no início do container (CMD do Dockerfile) e no "init" do CLI. Um advisory lock do Postgres
garante que duas instâncias subindo juntas (rolling update start-first) não façam isso ao mesmo tempo.

    python -m app.bootstrap
"""
import logging
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.keys import ensure_active_key
from app.db.session import make_engine

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "db" / "migrations"
_LOCK_ID = 721_340_001  # número arbitrário e fixo para o pg_advisory_lock desta aplicação


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return cfg


def bootstrap(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    engine = make_engine(settings)
    try:
        with engine.connect() as conn:
            postgres = conn.dialect.name == "postgresql"
            if postgres:
                conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _LOCK_ID})
                conn.commit()
            try:
                cfg = alembic_config()
                cfg.attributes["connection"] = conn
                command.upgrade(cfg, "head")

                with Session(bind=conn, expire_on_commit=False) as session:
                    key, created = ensure_active_key(session, settings.APP_MASTER_KEY)
                    session.commit()
                if created:
                    logger.info(f"Primeira chave JWT criada (kid={key.kid})")
            finally:
                if postgres:
                    conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _LOCK_ID})
                    conn.commit()
    finally:
        engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    try:
        bootstrap()
    except Exception as e:
        logger.error(f"Falha ao preparar o banco: {e}")
        sys.exit(1)
    logger.info("Banco pronto")
