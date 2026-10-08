import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.ad.client import ActiveDirectory, ADUnavailableError
from app.api import docs, tags
from app.api.v1 import auth, directory
from app.core.clients import ClientStore
from app.core.config import get_settings
from app.core.tokens import TokenService
from app.db.session import make_engine, make_session_factory

settings = get_settings()

logging.basicConfig(
    level=settings.LOG_LEVEL.upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    app.state.engine = engine
    app.state.ad = ActiveDirectory(settings)
    app.state.tokens = TokenService(settings, session_factory)
    app.state.clients = ClientStore(session_factory)
    yield
    engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.4.0",
    description="Autenticação e autorização centralizada no Active Directory on-premises.",
    lifespan=lifespan,
    # Documentação padrão desligada: as rotas protegidas por usuário/senha estão em app/api/docs.py
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    openapi_tags=[
        {"name": tags.BASIC_AUTH, "description": "Qualquer aplicação. Devolve só login, e-mail e status."},
        {"name": tags.FULL_AUTH, "description": "Só aplicações com `access_level=full`."},
        {"name": tags.DIRECTORY, "description": "Só aplicações `full` com `allow_directory_lookup`."},
        {"name": tags.TOKENS},
        {"name": tags.HEALTH},
    ],
)

app.include_router(auth.basic_router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(directory.router, prefix="/api/v1")
app.include_router(docs.router)


@app.get("/.well-known/jwks.json", tags=[tags.TOKENS], summary="Chave pública para validar os JWT localmente")
def jwks(request: Request):
    return request.app.state.tokens.jwks()


@app.get("/health", tags=[tags.HEALTH], summary="Liveness")
def health():
    return {"status": "ok"}


@app.get("/health/ready", tags=[tags.HEALTH], summary="Readiness: testa o banco e o bind da conta de serviço no AD")
def ready(request: Request):
    checks = {}
    try:
        with request.app.state.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        logging.getLogger(__name__).error(f"Banco indisponível: {e}")
        checks["database"] = "unavailable"
    try:
        request.app.state.ad.ping()
        checks["active_directory"] = "ok"
    except ADUnavailableError as e:
        checks["active_directory"] = f"unavailable: {e}"

    if all(v == "ok" for v in checks.values()):
        return {"status": "ok", **checks}
    return JSONResponse(status_code=503, content={"status": "unavailable", **checks})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
