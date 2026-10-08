"""Tabelas iniciais: clients e signing_keys

Revision ID: 0001
Revises:
Create Date: 2026-10-04
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("client_id", sa.String(63), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("access_level", sa.String(10), nullable=False, server_default="basic"),
        sa.Column("api_key_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("group_prefixes", sa.JSON(), nullable=False),
        sa.Column("required_groups", sa.JSON(), nullable=False),
        sa.Column("allow_directory_lookup", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("docs_username", sa.String(64), nullable=True, unique=True),
        sa.Column("docs_password_hash", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("access_level IN ('basic', 'full')", name="ck_clients_access_level"),
    )
    op.create_table(
        "signing_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kid", sa.String(64), nullable=False, unique=True),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_signing_keys_active",
        "signing_keys",
        ["active"],
        unique=True,
        postgresql_where=sa.text("active"),
        sqlite_where=sa.text("active"),
    )


def downgrade() -> None:
    op.drop_index("uq_signing_keys_active", table_name="signing_keys")
    op.drop_table("signing_keys")
    op.drop_table("clients")
