import re
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

from app.core.security_utils import decrypt_value

BASE_DIR = Path(__file__).resolve().parents[2]
# Desenvolvimento local: variáveis em config/app.env. Em produção vêm do variables.env (env_file da stack).
CONFIG_DIR = BASE_DIR / "config"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=CONFIG_DIR / "app.env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Active Directory API"
    LOG_LEVEL: str = "INFO"

    # Chave mestra (Fernet) usada para descriptografar segredos do .env
    APP_MASTER_KEY: str = ""

    # --- Active Directory ---
    AD_SSL: bool = False
    AD_SERVER: str = ""
    AD_PORT: int | None = None  # Se vazio: 636 com SSL, 389 sem SSL
    AD_DOMAIN: str = "example.local"
    AD_BASE_DOMAIN: str = "DC=example,DC=local"
    AD_CERTS: str | None = None  # CA do AD para validar o LDAPS
    AD_CONNECT_TIMEOUT: int = 5
    AD_RECEIVE_TIMEOUT: int = 10
    # Resolve grupos aninhados (grupo dentro de grupo). Mais custoso, por isso opcional.
    AD_NESTED_GROUPS: bool = False

    # Conta de serviço: usada no readiness e nas consultas de diretório (/users, /groups)
    AD_USER: str = ""
    AD_PASSWORD: str = ""  # Pode estar criptografada com APP_MASTER_KEY

    # --- JWT (a chave de assinatura fica no banco, criptografada com APP_MASTER_KEY) ---
    JWT_ISSUER: str = "active-directory-api"
    JWT_EXPIRES_MINUTES: int = 480

    # --- Banco (aplicações clientes e chaves JWT) ---
    DATABASE_VENDOR: str = "postgresql+psycopg2"
    DATABASE_HOST: str = "localhost"
    DATABASE_PORT: int = 5432
    DATABASE_NAME: str = "active_directory_api"
    DATABASE_SCHEMA: str = "active_directory_api"
    DATABASE_USER: str = ""
    DATABASE_PASSWORD: str = ""  # Pode estar criptografada com APP_MASTER_KEY
    DATABASE_SHOW_SQL: bool = False
    # Se preenchida, substitui as DATABASE_* acima (usado nos testes com SQLite)
    DATABASE_URL: str = ""

    @field_validator("DATABASE_SCHEMA")
    @classmethod
    def _valid_schema(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value):
            raise ValueError("DATABASE_SCHEMA deve conter só letras minúsculas, números e _")
        return value

    @property
    def ad_port(self) -> int:
        return self.AD_PORT or (636 if self.AD_SSL else 389)

    def _secret(self, value: str) -> str:
        if self.APP_MASTER_KEY and value:
            return decrypt_value(value, self.APP_MASTER_KEY) or ""
        return value

    @property
    def ad_service_password(self) -> str:
        return self._secret(self.AD_PASSWORD)

    @property
    def database_url(self) -> str | URL:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        # URL.create escapa caracteres especiais da senha (@, :, /...)
        return URL.create(
            self.DATABASE_VENDOR,
            username=self.DATABASE_USER,
            password=self._secret(self.DATABASE_PASSWORD),
            host=self.DATABASE_HOST,
            port=self.DATABASE_PORT,
            database=self.DATABASE_NAME,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
