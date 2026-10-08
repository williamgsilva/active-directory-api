#!/bin/bash
# Sobe (ou atualiza) a stack. Aplicações e chave JWT vêm do PostgreSQL; variáveis do variables.env.
cd "$(dirname "$0")" || exit 1

PROJECT="active-directory-api"
DT=$(date +%d-%m-%y--%H:%M:%S)
echo "Iniciando SWARM SERVICE - $PROJECT - $DT"
docker stack deploy -c docker-project.yml $PROJECT --with-registry-auth
