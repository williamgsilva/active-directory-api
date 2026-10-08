"""
Administração das aplicações clientes e da chave JWT, gravadas no PostgreSQL.

Usa as mesmas variáveis da API (DATABASE_*, APP_MASTER_KEY...). No servidor rode pelo
./admin.sh, que executa este CLI dentro da imagem com o variables.env.

    python -m app.cli                       # menu interativo
    python -m app.cli init                  # prepara o banco (migrations + 1ª chave JWT) e cadastra a 1ª aplicação
    python -m app.cli add | edit | list | rotate | remove
    python -m app.cli rotate-jwt            # nova chave de assinatura (a anterior vale até os tokens dela expirarem)
    python -m app.cli keys                  # lista as chaves JWT
    python -m app.cli encrypt               # criptografa AD_PASSWORD / DATABASE_PASSWORD para o variables.env
    python -m app.cli import-clients <arquivo.json>   # importa um clients.json do formato antigo

Toda alteração vale na hora para a API, sem restart.
"""
import getpass
import json
import re
import secrets
import sys
import unicodedata
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.bootstrap import bootstrap
from app.core.config import get_settings
from app.core.keys import KeyEncryptionError, list_keys, rotate_key
from app.core.security_utils import encrypt_value, generate_api_key, generate_key, hash_password
from app.db.models import ClientModel
from app.db.session import make_engine, make_session_factory

_CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")

_session_factory = None


def db() -> Session:
    global _session_factory
    if _session_factory is None:
        _session_factory = make_session_factory(make_engine(get_settings()))
    return _session_factory()


# ---------------------------------------------------------------------- utilitários

def clean(text: str) -> str:
    """
    Descarta bytes inválidos do terminal. Ex.: apagar uma letra acentuada com Backspace dentro do
    "docker run -it" pode deixar meio caractere UTF-8 para trás, que o Python guarda como surrogate
    e o banco recusa. Também normaliza acentos (NFC) para "ã" digitado de formas diferentes ser igual.
    """
    return unicodedata.normalize("NFC", text.encode("utf-8", "surrogateescape").decode("utf-8", "ignore"))


def read_line(prompt: str) -> str:
    return clean(input(prompt))


def read_secret(prompt: str) -> str:
    return clean(getpass.getpass(prompt))


def ask(prompt: str, default: str | None = None, validate=None, error: str = "Valor inválido.") -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = read_line(f"{prompt}{suffix}: ").strip() or (default or "")
        if value and (validate is None or validate(value)):
            return value
        print(f"  ! {error}")


def ask_list(prompt: str, current: list[str] | None = None) -> list[str]:
    if current is None:
        raw = read_line(f"{prompt} (separados por vírgula, vazio = nenhum): ").strip()
    else:
        shown = ", ".join(current) or "nenhum"
        raw = read_line(f"{prompt} [{shown}] (Enter mantém, - limpa): ").strip()
        if not raw:
            return list(current)
        if raw == "-":
            return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def ask_bool(prompt: str, default: bool = False) -> bool:
    hint = "S/n" if default else "s/N"
    raw = read_line(f"{prompt} [{hint}]: ").strip().lower()
    return default if not raw else raw in ("s", "sim", "y", "yes")


def ask_access_level(current: str = "basic") -> str:
    print("\nNível de acesso:")
    print("  1) básico   - login devolve só login, e-mail e status (endpoints /api/v1/auth/basic/*)")
    print("  2) completo - também dados completos e grupos do usuário, introspect, authorize e diretório")
    default = "2" if current == "full" else "1"
    choice = ask("Opção", default, validate=lambda v: v in ("1", "2"), error="Escolha 1 ou 2.")
    return "full" if choice == "2" else "basic"


def ask_docs_credentials(
    session: Session, client_id: str, current_user: str | None = None, confirm: bool = True
) -> tuple[str, str] | None:
    """Pergunta usuário/senha da documentação. Devolve (usuário, senha em texto) ou None se não liberar."""
    if confirm and not ask_bool("\nLiberar acesso à documentação (/docs e /redoc) com usuário e senha?", True):
        return None
    taken = set(
        session.scalars(
            select(ClientModel.docs_username).where(
                ClientModel.client_id != client_id, ClientModel.docs_username.is_not(None)
            )
        )
    )
    username = ask(
        "Usuário da documentação",
        current_user or client_id,
        validate=lambda v: v not in taken and ":" not in v and len(v) <= 64,
        error="Usuário já usado por outra aplicação ou inválido (não use ':').",
    )
    password = read_secret("Senha (Enter = gerar uma aleatória): ")
    if not password:
        return username, secrets.token_urlsafe(18)
    if len(password) < 12:
        print("  ! Mínimo de 12 caracteres. Gerando uma aleatória.")
        return username, secrets.token_urlsafe(18)
    if read_secret("Confirme a senha: ") != password:
        print("  ! Senhas diferentes. Gerando uma aleatória.")
        return username, secrets.token_urlsafe(18)
    return username, password


def apply_docs_credentials(row: ClientModel, creds: tuple[str, str] | None) -> None:
    row.docs_username = creds[0] if creds else None
    row.docs_password_hash = hash_password(creds[1]) if creds else None


def summary(row: ClientModel) -> dict:
    return {
        "client_id": row.client_id,
        "description": row.description,
        "access_level": row.access_level,
        "group_prefixes": row.group_prefixes,
        "required_groups": row.required_groups,
        "allow_directory_lookup": row.allow_directory_lookup,
        "documentação": f"usuário '{row.docs_username}'" if row.docs_username else "sem acesso",
    }


def show_secrets(client_id: str, api_key: str | None = None, docs: tuple[str, str] | None = None) -> None:
    print()
    print("=" * 72)
    print(f"  Credenciais de '{client_id}' (exibidas SOMENTE agora, guarde no cofre):")
    if api_key:
        print()
        print(f"  API key:  {api_key}")
        print("  A aplicação envia no header:  X-API-Key: <api key>")
    if docs:
        print()
        print("  Documentação (/docs e /redoc):")
        print(f"    usuário: {docs[0]}")
        print(f"    senha:   {docs[1]}")
    print("=" * 72)
    print()


def choose_client(session: Session) -> ClientModel | None:
    clients = list(session.scalars(select(ClientModel).order_by(ClientModel.client_id)))
    if not clients:
        print("Nenhuma aplicação cadastrada.")
        return None
    for i, c in enumerate(clients, 1):
        print(f"  {i}) {c.client_id}  {c.description}")
    choice = read_line("Número ou client_id (vazio = cancelar): ").strip()
    if not choice:
        return None
    if choice.isdigit() and 1 <= int(choice) <= len(clients):
        return clients[int(choice) - 1]
    for c in clients:
        if c.client_id == choice:
            return c
    print("  ! Aplicação não encontrada.")
    return None


# ---------------------------------------------------------------------- comandos

def cmd_init() -> None:
    print("\n=== Inicialização ===")
    print("✔ Banco pronto (migrations aplicadas e chave JWT ativa)")
    with db() as session:
        has_clients = session.scalar(select(ClientModel.id).limit(1)) is not None
    if not has_clients and ask_bool("\nNenhuma aplicação cadastrada. Cadastrar a primeira agora?", True):
        cmd_add()


def cmd_add() -> None:
    with db() as session:
        existing = set(session.scalars(select(ClientModel.client_id)))

        print("\n=== Nova aplicação cliente ===")
        client_id = ask(
            "client_id (minúsculas, números, - e _; ex.: deploy-app, portal-rh)",
            validate=lambda v: _CLIENT_ID.match(v) and v not in existing,
            error="Formato inválido ou client_id já cadastrado.",
        )
        row = ClientModel(client_id=client_id, description=read_line("Descrição: ").strip())
        row.access_level = ask_access_level()
        row.group_prefixes, row.required_groups, row.allow_directory_lookup = [], [], False

        if row.access_level == "full":
            print("\nPrefixos de grupo: só os grupos do AD que começam com eles vão para o token da aplicação.")
            print("  Ex.: GRP_APP_   (vazio = envia TODOS os grupos do usuário)")
            row.group_prefixes = ask_list("Prefixos")
        print("\nGrupos obrigatórios: o login só é aceito se o usuário estiver em pelo menos um deles.")
        row.required_groups = ask_list("Grupos obrigatórios")
        if row.access_level == "full":
            row.allow_directory_lookup = ask_bool("\nPermitir consultas ao diretório (/users e /groups)?", False)

        docs = ask_docs_credentials(session, client_id)
        apply_docs_credentials(row, docs)

        print("\nResumo:")
        print(json.dumps(summary(row), indent=2, ensure_ascii=False))
        if not ask_bool("Confirmar cadastro?", True):
            print("Cancelado.")
            return

        api_key, row.api_key_sha256 = generate_api_key()
        session.add(row)
        session.commit()
    print(f"✔ '{client_id}' cadastrada.")
    show_secrets(client_id, api_key=api_key, docs=docs)


def cmd_edit() -> None:
    with db() as session:
        row = choose_client(session)
        if not row:
            return
        cid = row.client_id
        print(f"\n=== Editando '{cid}' (Enter mantém o valor atual) ===")
        row.description = read_line(f"Descrição [{row.description}]: ").strip() or row.description
        row.access_level = ask_access_level(row.access_level)

        if row.access_level == "full":
            row.group_prefixes = ask_list("Prefixos de grupo", row.group_prefixes)
        row.required_groups = ask_list("Grupos obrigatórios", row.required_groups)
        if row.access_level == "full":
            row.allow_directory_lookup = ask_bool(
                "Permitir consultas ao diretório (/users e /groups)?", row.allow_directory_lookup
            )
        else:
            row.allow_directory_lookup = False

        docs = None
        print(f"\nDocumentação: {f'usuário {row.docs_username!r}' if row.docs_username else 'sem acesso'}")
        print("  1) manter   2) definir/trocar usuário e senha   3) remover acesso")
        docs_choice = ask("Opção", "1", validate=lambda v: v in ("1", "2", "3"), error="Escolha 1, 2 ou 3.")
        if docs_choice == "2":
            docs = ask_docs_credentials(session, cid, row.docs_username, confirm=False)
            apply_docs_credentials(row, docs)
        elif docs_choice == "3":
            apply_docs_credentials(row, None)

        print("\nResultado:")
        print(json.dumps(summary(row), indent=2, ensure_ascii=False))
        if not ask_bool("Salvar alterações?", True):
            session.rollback()
            print("Cancelado.")
            return
        session.commit()
    print(f"✔ '{cid}' atualizada.")
    if docs:
        show_secrets(cid, docs=docs)


def cmd_list() -> None:
    with db() as session:
        clients = list(session.scalars(select(ClientModel).order_by(ClientModel.client_id)))
    if not clients:
        print("Nenhuma aplicação cadastrada.")
        return
    print()
    for c in clients:
        print(f"• {c.client_id}  {c.description}")
        print(f"    nível de acesso: {'completo' if c.access_level == 'full' else 'básico'}")
        print(f"    prefixos: {', '.join(c.group_prefixes) or '(todos os grupos)'}")
        print(f"    obrigatórios: {', '.join(c.required_groups) or '(nenhum)'}")
        print(f"    consulta ao diretório: {'sim' if c.allow_directory_lookup else 'não'}")
        print(f"    documentação: {('usuário ' + c.docs_username) if c.docs_username else 'sem acesso'}")
        print(f"    atualizada em: {c.updated_at:%d/%m/%Y %H:%M}")


def cmd_rotate() -> None:
    with db() as session:
        row = choose_client(session)
        if not row:
            return
        if not ask_bool(f"A key atual de '{row.client_id}' para de funcionar imediatamente. Continuar?", False):
            return
        api_key, row.api_key_sha256 = generate_api_key()
        session.commit()
        cid = row.client_id
    print("✔ Key trocada.")
    show_secrets(cid, api_key=api_key)


def cmd_remove() -> None:
    with db() as session:
        row = choose_client(session)
        if not row:
            return
        if not ask_bool(f"Remover '{row.client_id}'? Ela perde o acesso imediatamente.", False):
            return
        cid = row.client_id
        session.delete(row)
        session.commit()
    print(f"✔ '{cid}' removida.")


def cmd_rotate_jwt() -> None:
    minutes = get_settings().JWT_EXPIRES_MINUTES
    print("\nUma nova chave passa a assinar os tokens. A atual continua validando os tokens já emitidos")
    print(f"por até {minutes} minutos (JWT_EXPIRES_MINUTES); depois disso deixa de valer.")
    if not ask_bool("Gerar nova chave JWT?", False):
        print("Cancelado.")
        return
    with db() as session:
        row = rotate_key(session, get_settings().APP_MASTER_KEY)
        session.commit()
        kid = row.kid
    print(f"✔ Nova chave ativa (kid={kid}). A API passa a usá-la em até 30 segundos.")


def cmd_keys() -> None:
    minutes = get_settings().JWT_EXPIRES_MINUTES
    now = datetime.now(timezone.utc)
    with db() as session:
        keys = list_keys(session)
    print()
    for k in keys:
        if k.active:
            status = "ATIVA (assina os tokens)"
        elif k.retired_at and (now - k.retired_at).total_seconds() < minutes * 60:
            status = f"aposentada em {k.retired_at:%d/%m/%Y %H:%M}, ainda valida tokens antigos"
        else:
            status = f"aposentada em {k.retired_at:%d/%m/%Y %H:%M}, expirada"
        print(f"• {k.kid}  criada em {k.created_at:%d/%m/%Y %H:%M}  {status}")


def cmd_encrypt() -> None:
    print("\n=== Criptografar valor para o variables.env (AD_PASSWORD, DATABASE_PASSWORD) ===")
    master_key = read_line("APP_MASTER_KEY atual (vazio = gerar uma nova): ").strip()
    new_key = not master_key
    if new_key:
        master_key = generate_key()
        print("  Atenção: com uma APP_MASTER_KEY nova, TODOS os valores criptografados do variables.env")
        print("  e a chave JWT guardada no banco precisam ter sido criados com ela.")
    variable = ask("Variável", "AD_PASSWORD", validate=lambda v: re.fullmatch(r"[A-Z_][A-Z0-9_]*", v))
    value = ""
    while not value:
        value = read_secret("Valor (não aparece ao digitar): ")
    try:
        encrypted = encrypt_value(value, master_key)
    except Exception as e:
        print(f"  ! APP_MASTER_KEY inválida: {e}")
        return
    print("\nColoque no variables.env e reinicie o serviço (./start.sh):\n")
    if new_key:
        print(f"APP_MASTER_KEY={master_key}")
    print(f"{variable}={encrypted}\n")


def cmd_import_clients(path: str | None = None) -> None:
    """Importa aplicações de um clients.json do formato antigo (arquivo/docker config). Pula as já existentes."""
    if not path:
        print("Uso: import-clients <arquivo.json>")
        return
    with open(path, encoding="utf-8") as f:
        items = json.load(f).get("clients", [])
    imported, skipped = [], []
    with db() as session:
        existing = set(session.scalars(select(ClientModel.client_id)))
        for item in items:
            if item["client_id"] in existing:
                skipped.append(item["client_id"])
                continue
            session.add(
                ClientModel(
                    client_id=item["client_id"],
                    description=item.get("description", ""),
                    access_level=item.get("access_level", "basic"),
                    api_key_sha256=item["api_key_sha256"].lower(),
                    group_prefixes=item.get("group_prefixes", []),
                    required_groups=item.get("required_groups", []),
                    allow_directory_lookup=bool(item.get("allow_directory_lookup", False)),
                    docs_username=item.get("docs_username") or None,
                    docs_password_hash=item.get("docs_password_hash") or None,
                )
            )
            imported.append(item["client_id"])
        session.commit()
    print(f"✔ Importadas: {', '.join(imported) or 'nenhuma'}")
    if skipped:
        print(f"• Já existiam (mantidas): {', '.join(skipped)}")
    print("As API keys continuam as mesmas: o arquivo guarda só os hashes.")


COMMANDS = {
    "init": ("Inicializar (banco + 1ª aplicação)", cmd_init),
    "add": ("Cadastrar nova aplicação", cmd_add),
    "edit": ("Editar aplicação (nível de acesso, grupos, documentação)", cmd_edit),
    "list": ("Listar aplicações", cmd_list),
    "rotate": ("Trocar a API key de uma aplicação", cmd_rotate),
    "remove": ("Remover aplicação", cmd_remove),
    "rotate-jwt": ("Gerar nova chave JWT", cmd_rotate_jwt),
    "keys": ("Listar chaves JWT", cmd_keys),
    "encrypt": ("Criptografar senha para o variables.env", cmd_encrypt),
}
# Não precisam do banco
_OFFLINE = {"encrypt"}


def menu() -> None:
    options = list(COMMANDS.items())
    while True:
        print("\n=== Active Directory API - Administração ===")
        for i, (_, (label, _)) in enumerate(options, 1):
            print(f"  {i}) {label}")
        print("  0) Sair")
        choice = read_line("Opção: ").strip()
        if choice in ("0", "", "q"):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            options[int(choice) - 1][1][1]()
        else:
            print("  ! Opção inválida.")


def main() -> int:
    args = sys.argv[1:]
    command = args[0] if args else None
    if command not in (None, "import-clients", *COMMANDS):
        print(__doc__)
        return 2
    try:
        if command not in _OFFLINE:
            # Idempotente: garante tabelas e chave JWT antes de qualquer operação
            bootstrap()
        if command is None:
            menu()
        elif command == "import-clients":
            cmd_import_clients(args[1] if len(args) > 1 else None)
        else:
            COMMANDS[command][1]()
    except (KeyboardInterrupt, EOFError):
        print("\nInterrompido.")
        return 130
    except OperationalError as e:
        print(f"\nERRO: não foi possível acessar o banco ({get_settings().DATABASE_HOST}): {e.orig}")
        return 1
    except KeyEncryptionError as e:
        print(f"\nERRO: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
