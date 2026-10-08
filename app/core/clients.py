"""
Registro das aplicações que consomem esta API (tabela clients no PostgreSQL).

Cada aplicação se identifica pelo header `X-API-Key`. No banco guardamos apenas o SHA-256 da chave,
nunca a chave em si. Cadastro e alterações pelo CLI (python -m app.cli / admin.sh).
A API consulta o banco a cada requisição: mudanças valem na hora, sem restart.

access_level:
    basic  login devolve só login, e-mail e status (endpoints /auth/basic/*)
    full   também os endpoints completos: dados e grupos do usuário, introspect, authorize e diretório

docs_username/docs_password_hash (opcionais): credencial HTTP Basic para abrir /docs, /redoc e /openapi.json.
"""
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.security_utils import hash_api_key, hash_password, verify_password
from app.db.models import ClientModel

logger = logging.getLogger(__name__)

ACCESS_LEVELS = ("basic", "full")
# Hash de uma senha qualquer: comparado quando o usuário da documentação não existe, para o tempo de
# resposta não revelar quais usuários existem
_DUMMY_PASSWORD_HASH = hash_password("dummy")


@dataclass(frozen=True)
class ClientApp:
    client_id: str
    api_key_sha256: str
    description: str = ""
    # Só estes grupos vão para o token/resposta dessa aplicação. Vazio = todos os grupos do usuário.
    group_prefixes: tuple[str, ...] = field(default_factory=tuple)
    # Se o login exigir pertencer a pelo menos um destes grupos. Vazio = qualquer usuário válido do AD.
    required_groups: tuple[str, ...] = field(default_factory=tuple)
    # Libera os endpoints de consulta ao diretório (/users, /groups) que usam a conta de serviço. Exige access_level full.
    allow_directory_lookup: bool = False
    access_level: str = "basic"
    docs_username: str | None = None
    docs_password_hash: str | None = None

    @property
    def is_full(self) -> bool:
        return self.access_level == "full"

    def filter_groups(self, groups: list[str]) -> list[str]:
        if not self.group_prefixes:
            return list(groups)
        prefixes = tuple(p.upper() for p in self.group_prefixes)
        return [g for g in groups if g.upper().startswith(prefixes)]

    def is_allowed(self, groups: list[str]) -> bool:
        if not self.required_groups:
            return True
        user_groups = {g.upper() for g in groups}
        return any(g.upper() in user_groups for g in self.required_groups)


def to_client_app(row: ClientModel) -> ClientApp:
    return ClientApp(
        client_id=row.client_id,
        api_key_sha256=row.api_key_sha256,
        description=row.description or "",
        group_prefixes=tuple(row.group_prefixes or ()),
        required_groups=tuple(row.required_groups or ()),
        allow_directory_lookup=bool(row.allow_directory_lookup),
        access_level=row.access_level,
        docs_username=row.docs_username,
        docs_password_hash=row.docs_password_hash,
    )


class ClientStore:
    def __init__(self, session_factory: sessionmaker[Session]):
        self._session_factory = session_factory

    def authenticate(self, api_key: str | None) -> ClientApp | None:
        if not api_key:
            return None
        # Busca pelo hash (índice único): comparar hashes de uma chave aleatória longa não vaza nada útil
        with self._session_factory() as session:
            row = session.scalar(select(ClientModel).where(ClientModel.api_key_sha256 == hash_api_key(api_key)))
            return to_client_app(row) if row else None

    def authenticate_docs(self, username: str, password: str) -> ClientApp | None:
        """Credencial HTTP Basic da documentação."""
        with self._session_factory() as session:
            row = session.scalar(select(ClientModel).where(ClientModel.docs_username == username))
            client = to_client_app(row) if row else None
        if client is None or not client.docs_password_hash:
            verify_password(password, _DUMMY_PASSWORD_HASH)
            return None
        return client if verify_password(password, client.docs_password_hash) else None
