from fastapi import APIRouter, HTTPException, status

from app.ad.client import ADUnavailableError, InvalidCredentialsError
from app.api import tags
from app.api.deps import AD, DirectoryClient
from app.api.schemas import GroupMembersResponse, UserInfo
from app.api.v1.auth import ad_unavailable, to_user_info

router = APIRouter(tags=[tags.DIRECTORY])


@router.get(
    "/users/{username}",
    response_model=UserInfo,
    summary="Consulta dados e grupos atuais de um usuário no AD (login ou e-mail)",
    description="Útil para revalidar permissões sem pedir a senha de novo. Requer `allow_directory_lookup`.",
)
def get_user(username: str, client: DirectoryClient, ad: AD):
    try:
        user = ad.get_user(username)
    except InvalidCredentialsError:
        user = None
    except ADUnavailableError as e:
        raise ad_unavailable(e)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    return to_user_info(user, client)


@router.get(
    "/groups/{group}/members",
    response_model=GroupMembersResponse,
    summary="Lista os membros de um grupo do AD",
    description="Só grupos dentro dos `group_prefixes` da aplicação podem ser consultados.",
)
def get_group_members(group: str, client: DirectoryClient, ad: AD):
    if not client.filter_groups([group]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo fora do escopo da aplicação")
    try:
        members = ad.get_group_members(group)
    except ADUnavailableError as e:
        raise ad_unavailable(e)
    if members is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo não encontrado")
    return GroupMembersResponse(group=group, members=members)
