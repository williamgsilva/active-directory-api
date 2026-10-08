from alembic import context
from sqlalchemy import text

from app.core.config import get_settings
from app.db.models import Base
from app.db.session import make_engine

target_metadata = Base.metadata


def run_on(connection) -> None:
    if connection.dialect.name == "postgresql":
        # O search_path da conexão aponta para este schema; ele precisa existir antes das tabelas
        schema = get_settings().DATABASE_SCHEMA
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
        connection.commit()
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # app.bootstrap passa a conexão (com o advisory lock); o comando "alembic" sozinho cria a sua
    connection = context.config.attributes.get("connection")
    if connection is not None:
        run_on(connection)
        return
    with make_engine(get_settings()).connect() as connection:
        run_on(connection)


if context.is_offline_mode():
    raise SystemExit("Modo offline não suportado: rode as migrations contra o banco.")
run_migrations_online()
