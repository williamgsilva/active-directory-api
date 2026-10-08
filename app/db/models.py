from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Index, String, Text, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ClientModel(Base):
    """Aplicação que consome a API (antes: clients.json)."""

    __tablename__ = "clients"
    __table_args__ = (CheckConstraint("access_level IN ('basic', 'full')", name="ck_clients_access_level"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(String(63), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    access_level: Mapped[str] = mapped_column(String(10), default="basic")
    # Só o SHA-256 da API key; a key em si é mostrada uma única vez no cadastro
    api_key_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    group_prefixes: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_groups: Mapped[list[str]] = mapped_column(JSON, default=list)
    allow_directory_lookup: Mapped[bool] = mapped_column(default=False)
    docs_username: Mapped[str | None] = mapped_column(String(64), unique=True)
    docs_password_hash: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SigningKeyModel(Base):
    """Chave RSA que assina os JWT. Só uma ativa; as aposentadas continuam validando tokens até expirarem."""

    __tablename__ = "signing_keys"
    __table_args__ = (
        # Garante no banco que nunca há duas chaves ativas
        Index(
            "uq_signing_keys_active",
            "active",
            unique=True,
            postgresql_where=text("active"),
            sqlite_where=text("active"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kid: Mapped[str] = mapped_column(String(64), unique=True)
    # PEM da chave privada criptografado com APP_MASTER_KEY (Fernet)
    private_key_encrypted: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
