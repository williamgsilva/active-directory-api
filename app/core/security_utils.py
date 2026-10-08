import hashlib
import logging
import secrets
import sys

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def generate_key() -> str:
    """Gera uma nova chave mestra (Fernet). Rode UMA VEZ e guarde a chave no cofre."""
    return Fernet.generate_key().decode()


def encrypt_value(plain_text: str, key: str) -> str:
    return Fernet(key.encode()).encrypt(plain_text.encode()).decode()


def decrypt_value(encrypted_text: str, key: str) -> str | None:
    try:
        return Fernet(key.encode()).decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        logger.error(f"Erro ao descriptografar valor: {e}")
        return None


def generate_api_key() -> tuple[str, str]:
    """Gera uma API key para uma aplicação cliente. Retorna (chave, sha256 da chave)."""
    key = secrets.token_urlsafe(32)
    return key, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# Senhas de acesso à documentação: scrypt (lento de propósito, ao contrário da API key que é aleatória e longa)
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt, digest = encoded.split("$")
        if algo != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(digest) // 2
        )
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(candidate.hex(), digest)


# Uso via CLI:
#   python -m app.core.security_utils master-key
#   python -m app.core.security_utils encrypt <MASTER_KEY> <valor>
#   python -m app.core.security_utils api-key
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "master-key":
        print(generate_key())
    elif cmd == "encrypt" and len(sys.argv) == 4:
        print(encrypt_value(sys.argv[3], sys.argv[2]))
    elif cmd == "api-key":
        key, digest = generate_api_key()
        print(f"API key (entregar para a aplicação): {key}")
        print(f"api_key_sha256 (colocar no clients.json): {digest}")
    else:
        print("Uso: python -m app.core.security_utils [master-key | encrypt <MASTER_KEY> <valor> | api-key]")
