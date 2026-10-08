from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=256,
        description="Login do AD (nome.sobrenome) ou e-mail cadastrado no AD (nome.sobrenome@example.com)",
        examples=["nome.sobrenome"],
    )
    password: str = Field(min_length=1, max_length=512)


class UserInfo(BaseModel):
    username: str
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    user_principal_name: str | None = None
    email: str | None = None
    last_password_change: datetime | None = None
    password_expires_at: datetime | None = None
    password_never_expires: bool = False
    password_expires_in_days: int | None = None
    last_logon: datetime | None = None
    is_active: bool = True
    groups: list[str] = []


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: UserInfo


class TokenRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    claims: dict | None = None
    error: str | None = None


class AuthorizeRequest(BaseModel):
    token: str
    groups: list[str] = Field(min_length=1, examples=[["GRP_APP_ADMIN"]])
    mode: Literal["any", "all"] = "any"


class AuthorizeResponse(BaseModel):
    authorized: bool
    username: str | None = None
    matched_groups: list[str] = []
    missing_groups: list[str] = []


class GroupMembersResponse(BaseModel):
    group: str
    members: list[str]


# --- Nível básico: só o mínimo para identificar o usuário ---

class BasicUserInfo(BaseModel):
    login: str
    email: str | None = None
    is_active: bool = True


class BasicLoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: BasicUserInfo


class BasicIntrospectResponse(BaseModel):
    active: bool
    login: str | None = None
    email: str | None = None
    expires_at: datetime | None = None
    error: str | None = None
