"""
Emissão e validação de JWT (RS256).

Usamos chave assimétrica para que as aplicações consigam validar o token localmente,
buscando a chave pública em /.well-known/jwks.json, sem precisar chamar esta API a cada requisição.

As chaves ficam no banco (tabela signing_keys, criptografadas com APP_MASTER_KEY) e são mantidas
em cache por alguns segundos. Depois de uma troca de chave (rotate-jwt), a anterior continua no JWKS
e validando tokens até o último token emitido com ela expirar.
"""
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.keys import decrypt_private_key, valid_keys

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
CACHE_SECONDS = 30


class NoSigningKeyError(RuntimeError):
    pass


@dataclass(frozen=True)
class _Key:
    kid: str
    active: bool
    private_key: rsa.RSAPrivateKey

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()


class TokenService:
    def __init__(self, settings: Settings, session_factory: sessionmaker[Session]):
        self.issuer = settings.JWT_ISSUER
        self.expires_minutes = settings.JWT_EXPIRES_MINUTES
        self._master_key = settings.APP_MASTER_KEY
        self._session_factory = session_factory
        self._keys: list[_Key] = []
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ chaves

    def _load(self) -> list[_Key]:
        with self._session_factory() as session:
            rows = valid_keys(session, timedelta(minutes=self.expires_minutes))
        return [_Key(kid=r.kid, active=r.active, private_key=decrypt_private_key(r, self._master_key)) for r in rows]

    def _get_keys(self, force: bool = False) -> list[_Key]:
        if not force and time.monotonic() - self._loaded_at < CACHE_SECONDS:
            return self._keys
        with self._lock:
            if force or time.monotonic() - self._loaded_at >= CACHE_SECONDS:
                self._keys = self._load()
                self._loaded_at = time.monotonic()
        return self._keys

    def _active(self) -> _Key:
        for key in self._get_keys():
            if key.active:
                return key
        raise NoSigningKeyError("Nenhuma chave JWT ativa no banco (rode: python -m app.bootstrap)")

    def _by_kid(self, kid: str | None) -> _Key | None:
        for force in (False, True):  # kid desconhecido: pode ser chave nova ainda fora do cache
            for key in self._get_keys(force=force):
                if key.kid == kid:
                    return key
        return None

    # ------------------------------------------------------------------ tokens

    def issue(self, subject: str, audience: str, claims: dict) -> tuple[str, int]:
        key = self._active()
        now = datetime.now(timezone.utc)
        expires_in = self.expires_minutes * 60
        payload = {
            **claims,
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=expires_in),
            "jti": uuid.uuid4().hex,
        }
        token = jwt.encode(payload, key.private_key, algorithm=ALGORITHM, headers={"kid": key.kid})
        return token, expires_in

    def decode(self, token: str, audience: str) -> dict:
        """Valida assinatura, expiração, emissor e audiência. Lança jwt.PyJWTError se inválido."""
        kid = jwt.get_unverified_header(token).get("kid")
        key = self._by_kid(kid)
        if key is None:
            raise jwt.InvalidKeyError("Token assinado por uma chave desconhecida ou já expirada")
        return jwt.decode(
            token,
            key.public_key,
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )

    def jwks(self) -> dict:
        keys = []
        for key in self._get_keys():
            jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key))
            jwk.update({"kid": key.kid, "use": "sig", "alg": ALGORITHM})
            keys.append(jwk)
        return {"keys": keys}
