"""Chaves RSA de assinatura dos JWT: geração, kid e criptografia para guardar no banco."""
import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.db.models import SigningKeyModel


class KeyEncryptionError(RuntimeError):
    pass


def _fernet(master_key: str) -> Fernet:
    if not master_key:
        raise KeyEncryptionError("APP_MASTER_KEY é obrigatória: a chave JWT é guardada criptografada no banco")
    try:
        return Fernet(master_key.encode())
    except ValueError as e:
        raise KeyEncryptionError(f"APP_MASTER_KEY inválida: {e}") from e


def kid_for(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()[:16]).decode().rstrip("=")


def decrypt_private_key(row: SigningKeyModel, master_key: str) -> rsa.RSAPrivateKey:
    try:
        pem = _fernet(master_key).decrypt(row.private_key_encrypted.encode())
    except InvalidToken as e:
        raise KeyEncryptionError(
            f"Não foi possível descriptografar a chave JWT '{row.kid}': APP_MASTER_KEY diferente da usada para criá-la"
        ) from e
    return serialization.load_pem_private_key(pem, password=None)


def new_key_row(master_key: str) -> SigningKeyModel:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return SigningKeyModel(
        kid=kid_for(key.public_key()),
        private_key_encrypted=_fernet(master_key).encrypt(pem).decode(),
        active=True,
    )


def get_active_key(session: Session) -> SigningKeyModel | None:
    return session.scalar(select(SigningKeyModel).where(SigningKeyModel.active.is_(True)))


def ensure_active_key(session: Session, master_key: str) -> tuple[SigningKeyModel, bool]:
    """Cria a primeira chave se não houver nenhuma ativa. Devolve (chave, criada_agora)."""
    current = get_active_key(session)
    if current is not None:
        return current, False
    row = new_key_row(master_key)
    session.add(row)
    session.flush()
    return row, True


def rotate_key(session: Session, master_key: str) -> SigningKeyModel:
    """Aposenta a chave ativa e cria outra. A aposentada continua validando tokens até eles expirarem."""
    row = new_key_row(master_key)
    session.execute(
        update(SigningKeyModel)
        .where(SigningKeyModel.active.is_(True))
        .values(active=False, retired_at=datetime.now(timezone.utc))
    )
    session.flush()
    session.add(row)
    session.flush()
    return row


def valid_keys(session: Session, token_lifetime: timedelta) -> list[SigningKeyModel]:
    """Chave ativa + aposentadas que ainda podem ter tokens válidos emitidos."""
    cutoff = datetime.now(timezone.utc) - token_lifetime
    return list(
        session.scalars(
            select(SigningKeyModel)
            .where(or_(SigningKeyModel.active.is_(True), SigningKeyModel.retired_at > cutoff))
            .order_by(SigningKeyModel.active.desc(), SigningKeyModel.created_at.desc())
        )
    )


def list_keys(session: Session) -> list[SigningKeyModel]:
    return list(session.scalars(select(SigningKeyModel).order_by(SigningKeyModel.created_at.desc())))
