#!/bin/bash
# Remove só o serviço. Aplicações e chave JWT continuam no PostgreSQL.
cd "$(dirname "$0")" || exit 1

PROJECT="active-directory-api"
DT=$(date +%d-%m-%y--%H:%M:%S)
echo "Removendo SWARM SERVICE - $PROJECT - $DT"
docker stack rm $PROJECT
