#!/usr/bin/env bash
# Administração da Active Directory API: aplicações clientes e chave JWT, gravadas no PostgreSQL.
# Roda o CLI da própria imagem com o variables.env. Precisa só de Docker e de acesso ao banco
# a partir desta máquina (não precisa ser manager do Swarm).
#
#   ./admin.sh                    menu
#   ./admin.sh init               prepara o banco (tabelas + 1ª chave JWT) e cadastra a 1ª aplicação
#   ./admin.sh add|edit|list|rotate|remove
#   ./admin.sh rotate-jwt|keys    troca / lista as chaves JWT
#   ./admin.sh encrypt            criptografa AD_PASSWORD / DATABASE_PASSWORD para o variables.env
#   ./admin.sh import-clients <clients.json>   migra aplicações do formato antigo
#
# Toda alteração vale na hora para a API, sem restart.
#
# Variáveis opcionais:
#   ENV_FILE   (padrão: ./variables.env)
#   IMAGE      (padrão: a imagem do serviço no Swarm, se existir; senão REGISTRY/active-directory-api:IMAGE_TAG)
#   NETWORK    rede Docker para alcançar o banco (padrão: host, o banco é acessado como desta máquina)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/variables.env}"
SERVICE="${SERVICE:-active-directory-api_api}"
NETWORK="${NETWORK:-host}"

die() { echo "ERRO: $*" >&2; exit 1; }

[[ -f $ENV_FILE ]] || die "Arquivo de variáveis não encontrado: $ENV_FILE"

if [[ -z ${IMAGE:-} ]]; then
  # Mesma versão que está rodando, para o CLI e a API concordarem sobre o banco.
  # Sem o serviço (1ª instalação) o inspect falha e imprime uma linha vazia: por isso o tr e o teste.
  IMAGE=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' "$SERVICE" 2>/dev/null \
    | tr -d '[:space:]' || true)
  [[ -n $IMAGE ]] || IMAGE="${REGISTRY:-registry.example.com}/active-directory-api:${IMAGE_TAG:-0.4.0}"
fi

args=(--rm -i --env-file "$ENV_FILE" --network "$NETWORK")
[[ -t 0 ]] && args+=(-t)

# import-clients <arquivo>: o arquivo precisa estar dentro do container
if [[ ${1:-} == import-clients ]]; then
  [[ -f ${2:-} ]] || die "Uso: $0 import-clients <clients.json>"
  args+=(-v "$(realpath "$2"):/tmp/import-clients.json:ro")
  set -- import-clients /tmp/import-clients.json
fi

exec docker run "${args[@]}" --entrypoint python "$IMAGE" -m app.cli "$@"
