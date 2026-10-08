"""
Documentação (Swagger, ReDoc e o schema OpenAPI) protegida por HTTP Basic.

Cada aplicação pode ter um usuário/senha próprio (docs_username/docs_password_hash na tabela clients,
definidos pelo admin.sh). Aplicações com access_level=basic só enxergam os endpoints básicos.
"""
import copy
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.api import tags
from app.api.deps import get_registry
from app.core.clients import ClientApp, ClientStore

REALM = "Active Directory API - Documentacao"
OPENAPI_URL = "/openapi.json"

_basic = HTTPBasic(auto_error=False, realm=REALM)

router = APIRouter(include_in_schema=False)


def require_docs_client(
    credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic)],
    registry: Annotated[ClientStore, Depends(get_registry)],
) -> ClientApp:
    client = registry.authenticate_docs(credentials.username, credentials.password) if credentials else None
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais da documentação inválidas",
            headers={"WWW-Authenticate": f'Basic realm="{REALM}"'},
        )
    return client


DocsClient = Annotated[ClientApp, Depends(require_docs_client)]


def schema_for(full_schema: dict, client: ClientApp) -> dict:
    if client.is_full:
        return full_schema
    schema = copy.deepcopy(full_schema)
    for path, operations in list(schema.get("paths", {}).items()):
        for method, operation in list(operations.items()):
            if tags.FULL_ONLY & set(operation.get("tags", [])):
                del operations[method]
        if not operations:
            del schema["paths"][path]
    schema["tags"] = [t for t in schema.get("tags", []) if t.get("name") not in tags.FULL_ONLY]
    return schema


@router.get(OPENAPI_URL)
def openapi(request: Request, client: DocsClient):
    return JSONResponse(schema_for(request.app.openapi(), client))


@router.get("/docs")
def swagger(request: Request, client: DocsClient):
    return get_swagger_ui_html(openapi_url=OPENAPI_URL, title=f"{request.app.title} - Swagger")


@router.get("/redoc")
def redoc(request: Request, client: DocsClient):
    return get_redoc_html(openapi_url=OPENAPI_URL, title=f"{request.app.title} - ReDoc")
