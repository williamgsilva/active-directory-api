"""
Integração com o Active Directory on-premises.

Cuidados de implementação:
  - Uma conexão por requisição (uma conexão compartilhada entre usuários, numa API concorrente,
    misturaria sessões).
  - Entradas do usuário escapadas antes de entrar em filtros LDAP (evita LDAP injection).
  - Senha vazia é rejeitada: no AD um simple bind com senha vazia vira "unauthenticated bind"
    e pode ser aceito sem validar nada.
  - Distingue credencial inválida de AD indisponível.
"""
import logging
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ldap3 import NONE, SIMPLE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPSocketReceiveError
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from app.core.config import Settings

logger = logging.getLogger(__name__)

# sAMAccountName não aceita estes caracteres; rejeitar cedo evita consultas estranhas no AD
_INVALID_USERNAME = re.compile(r'["/\\\[\]:;|=,+*?<>@\s]')
# Validação só de formato; o domínio do e-mail não é fixo, vale o que estiver no atributo "mail" do AD
_EMAIL = re.compile(r"^[^@\s()*\\]{1,64}@[^@\s()*\\]{1,190}\.[^@\s()*\\]{2,}$")

# Códigos "data XXX" devolvidos pelo AD no bind com falha (apenas para log)
_AD_BIND_REASONS = {
    "525": "usuário não encontrado",
    "52e": "senha inválida",
    "530": "horário de logon não permitido",
    "531": "estação não permitida",
    "532": "senha expirada",
    "533": "conta desabilitada",
    "701": "conta expirada",
    "773": "usuário precisa trocar a senha",
    "775": "conta bloqueada",
}

_USER_ATTRIBUTES = [
    "givenName",
    "sn",
    "displayName",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "distinguishedName",
    "whenCreated",
    "pwdLastSet",
    "msDS-UserPasswordExpiryTimeComputed",
    "lastLogonTimestamp",
    "memberOf",
    "userAccountControl",
]

_UAC_ACCOUNTDISABLE = 0x2
_UAC_DONT_EXPIRE_PASSWORD = 0x10000
_FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF


class ADError(Exception):
    pass


class InvalidCredentialsError(ADError):
    pass


class ADUnavailableError(ADError):
    pass


@dataclass
class ADUser:
    username: str
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    user_principal_name: str | None = None
    email: str | None = None
    distinguished_name: str | None = None
    created_at: datetime | None = None
    last_password_change: datetime | None = None
    password_expires_at: datetime | None = None
    password_never_expires: bool = False
    last_logon: datetime | None = None
    is_active: bool = True
    groups: list[str] = field(default_factory=list)


def normalize_username(raw: str) -> str:
    """Aceita 'usuario', 'usuario@dominio' ou 'DOMINIO\\usuario' e devolve apenas o sAMAccountName."""
    username = (raw or "").strip()
    if "\\" in username:
        username = username.split("\\", 1)[1]
    if "@" in username:
        username = username.split("@", 1)[0]
    if not username or len(username) > 64 or _INVALID_USERNAME.search(username):
        raise InvalidCredentialsError("Nome de usuário inválido")
    return username


def _filetime_to_datetime(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.year <= 1601 or value.year >= 9999:
            return None
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return None
    if ft <= 0 or ft >= _FILETIME_NEVER:
        return None
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)


def _cn_from_dn(dn: str) -> str:
    try:
        # Remove os escapes de DN (ex.: "Grupo\, X" -> "Grupo, X")
        return re.sub(r"\\(.)", r"\1", parse_dn(dn, escape=False)[0][1])
    except Exception:
        return dn.split(",")[0].removeprefix("CN=")


class ActiveDirectory:
    def __init__(self, settings: Settings):
        self.settings = settings
        tls = None
        if settings.AD_SSL:
            tls = Tls(
                validate=ssl.CERT_REQUIRED if settings.AD_CERTS else ssl.CERT_NONE,
                ca_certs_file=settings.AD_CERTS or None,
                version=ssl.PROTOCOL_TLS_CLIENT,
            )
            if not settings.AD_CERTS:
                logger.warning("AD_SSL ativo sem AD_CERTS: o certificado do AD NÃO será validado.")
        self.server = Server(
            settings.AD_SERVER,
            port=settings.ad_port,
            use_ssl=settings.AD_SSL,
            tls=tls,
            get_info=NONE,
            connect_timeout=settings.AD_CONNECT_TIMEOUT,
        )

    # ------------------------------------------------------------------ conexão

    def _bind(self, username: str, password: str) -> Connection:
        conn = Connection(
            self.server,
            user=f"{username}@{self.settings.AD_DOMAIN}",
            password=password,
            authentication=SIMPLE,
            receive_timeout=self.settings.AD_RECEIVE_TIMEOUT,
            raise_exceptions=False,
        )
        try:
            conn.open()
            if conn.bind():
                return conn
        except (LDAPSocketOpenError, LDAPSocketReceiveError) as e:
            logger.error(f"AD indisponível ({self.server}): {e}")
            raise ADUnavailableError("Não foi possível conectar ao Active Directory") from e
        except LDAPException as e:
            logger.error(f"Erro LDAP no bind de '{username}': {e}")
            raise ADUnavailableError("Erro ao comunicar com o Active Directory") from e

        message = (conn.result or {}).get("message", "")
        match = re.search(r"data ([0-9a-f]{3})", message)
        reason = _AD_BIND_REASONS.get(match.group(1), match.group(1)) if match else conn.result.get("description")
        logger.warning(f"Falha de autenticação no AD para '{username}': {reason}")
        conn.unbind()
        raise InvalidCredentialsError("Usuário ou senha inválidos")

    def _service_connection(self) -> Connection:
        if not self.settings.AD_USER or not self.settings.ad_service_password:
            raise ADUnavailableError("Conta de serviço do AD (AD_USER/AD_PASSWORD) não configurada")
        try:
            return self._bind(normalize_username(self.settings.AD_USER), self.settings.ad_service_password)
        except InvalidCredentialsError as e:
            logger.error("Credenciais da conta de serviço do AD inválidas")
            raise ADUnavailableError("Conta de serviço do AD com credenciais inválidas") from e

    # ------------------------------------------------------------------ consultas

    def _resolve_username(self, conn: Connection, identifier: str) -> str:
        """
        Converte o que o usuário digitou no sAMAccountName.
        Com "@", procura pelo atributo mail (ex.: nome@example.com) ou pelo userPrincipalName.
        Sem "@", é o próprio login (aceita também DOMINIO\\usuario).
        """
        identifier = (identifier or "").strip()
        if "@" not in identifier:
            return normalize_username(identifier)
        if not _EMAIL.match(identifier):
            raise InvalidCredentialsError("Usuário ou senha inválidos")

        value = escape_filter_chars(identifier)
        conn.search(
            search_base=self.settings.AD_BASE_DOMAIN,
            search_filter=f"(&(objectCategory=person)(objectClass=user)(|(mail={value})(userPrincipalName={value})))",
            attributes=["sAMAccountName"],
            size_limit=2,
        )
        entries = [e for e in conn.entries if "sAMAccountName" in e]
        if len(entries) == 1:
            return entries[0].sAMAccountName.value
        if len(entries) > 1:
            logger.warning(f"E-mail '{identifier}' pertence a mais de um usuário no AD: login por e-mail recusado")
            raise InvalidCredentialsError("Usuário ou senha inválidos")

        # Não achou: aceita "usuario@<AD_DOMAIN>" como antes (UPN implícito)
        local, _, domain = identifier.partition("@")
        if domain.lower() == self.settings.AD_DOMAIN.lower():
            return normalize_username(local)
        logger.warning(f"Nenhum usuário com o e-mail '{identifier}' no AD")
        raise InvalidCredentialsError("Usuário ou senha inválidos")

    def resolve_username(self, identifier: str) -> str:
        if "@" not in (identifier or ""):
            return normalize_username(identifier)
        # Login por e-mail precisa da conta de serviço: o bind é feito com o sAMAccountName
        conn = self._service_connection()
        try:
            return self._resolve_username(conn, identifier)
        finally:
            conn.unbind()

    def _search_user(self, conn: Connection, username: str) -> ADUser | None:
        conn.search(
            search_base=self.settings.AD_BASE_DOMAIN,
            search_filter=f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escape_filter_chars(username)}))",
            attributes=_USER_ATTRIBUTES,
        )
        if not conn.entries:
            return None
        user = self._parse_user_entry(conn.entries[0])
        if self.settings.AD_NESTED_GROUPS and user.distinguished_name:
            user.groups = self._nested_groups(conn, user.distinguished_name)
        return user

    def _nested_groups(self, conn: Connection, user_dn: str) -> list[str]:
        # LDAP_MATCHING_RULE_IN_CHAIN: devolve todos os grupos, inclusive os herdados por grupos aninhados
        entries = conn.extend.standard.paged_search(
            search_base=self.settings.AD_BASE_DOMAIN,
            search_filter=f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escape_filter_chars(user_dn)}))",
            attributes=["cn"],
            paged_size=500,
            generator=False,
        )
        return sorted({e["attributes"]["cn"] for e in entries if e.get("type") == "searchResEntry"})

    @staticmethod
    def _parse_user_entry(entry) -> ADUser:
        def value(attr):
            return entry[attr].value if attr in entry else None

        member_of = entry["memberOf"].values if "memberOf" in entry else []
        uac = int(value("userAccountControl") or 0)
        never_expires = bool(uac & _UAC_DONT_EXPIRE_PASSWORD)
        created = value("whenCreated")

        return ADUser(
            username=value("sAMAccountName"),
            first_name=value("givenName"),
            last_name=value("sn"),
            display_name=value("displayName"),
            user_principal_name=value("userPrincipalName"),
            email=value("mail"),
            distinguished_name=value("distinguishedName"),
            created_at=created if isinstance(created, datetime) else None,
            last_password_change=_filetime_to_datetime(value("pwdLastSet")),
            password_expires_at=None if never_expires else _filetime_to_datetime(value("msDS-UserPasswordExpiryTimeComputed")),
            password_never_expires=never_expires,
            last_logon=_filetime_to_datetime(value("lastLogonTimestamp")),
            is_active=not bool(uac & _UAC_ACCOUNTDISABLE),
            groups=sorted({_cn_from_dn(dn) for dn in member_of}),
        )

    # ------------------------------------------------------------------ API pública

    def authenticate(self, username: str, password: str) -> ADUser:
        """Valida login (ou e-mail) e senha com bind no AD e devolve os dados + grupos do usuário."""
        if not password:
            raise InvalidCredentialsError("Usuário ou senha inválidos")
        username = self.resolve_username(username)

        conn = self._bind(username, password)
        try:
            user = self._search_user(conn, username)
        finally:
            conn.unbind()

        if user is None:
            # Bind funcionou mas o objeto não está sob AD_BASE_DOMAIN
            logger.warning(f"Usuário '{username}' autenticou mas não foi encontrado em {self.settings.AD_BASE_DOMAIN}")
            raise InvalidCredentialsError("Usuário ou senha inválidos")
        if not user.is_active:
            raise InvalidCredentialsError("Usuário ou senha inválidos")
        return user

    def get_user(self, identifier: str) -> ADUser | None:
        """Consulta um usuário (login ou e-mail) com a conta de serviço, sem a senha dele."""
        conn = self._service_connection()
        try:
            return self._search_user(conn, self._resolve_username(conn, identifier))
        finally:
            conn.unbind()

    def get_group_members(self, group_name: str) -> list[str] | None:
        """Lista os sAMAccountName dos membros de um grupo. None se o grupo não existir."""
        conn = self._service_connection()
        try:
            conn.search(
                search_base=self.settings.AD_BASE_DOMAIN,
                search_filter=f"(&(objectClass=group)(cn={escape_filter_chars(group_name)}))",
                attributes=["distinguishedName"],
            )
            if not conn.entries:
                return None
            group_dn = conn.entries[0].distinguishedName.value
            rule = ":1.2.840.113556.1.4.1941:" if self.settings.AD_NESTED_GROUPS else ""
            entries = conn.extend.standard.paged_search(
                search_base=self.settings.AD_BASE_DOMAIN,
                search_filter=f"(&(objectCategory=person)(objectClass=user)(memberOf{rule}={escape_filter_chars(group_dn)}))",
                attributes=["sAMAccountName"],
                paged_size=500,
                generator=False,
            )
            return sorted(
                e["attributes"]["sAMAccountName"] for e in entries if e.get("type") == "searchResEntry"
            )
        finally:
            conn.unbind()

    def ping(self) -> None:
        """Verifica se o AD está acessível usando a conta de serviço."""
        self._service_connection().unbind()
