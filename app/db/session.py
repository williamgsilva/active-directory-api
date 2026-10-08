from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings


def make_engine(settings: Settings) -> Engine:
    url = settings.database_url
    if str(url).startswith("sqlite"):
        # Testes: banco em memória compartilhado entre threads
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    return create_engine(
        url,
        # Verifica a conexão antes de usar: o banco pode ter reiniciado ou derrubado conexões ociosas
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        echo=settings.DATABASE_SHOW_SQL,
        # Todas as tabelas (inclusive alembic_version) ficam no schema DATABASE_SCHEMA
        connect_args={"options": f"-csearch_path={settings.DATABASE_SCHEMA}", "application_name": "active-directory-api"},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
