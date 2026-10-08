# Active Directory API

API central de autenticação e autorização no **Active Directory on-premises**. As aplicações
deixam de falar direto com o AD e passam a chamar esta API, sem replicar a lógica de autenticação em cada uma.

```
 Aplicação ──(X-API-Key + usuário/senha)──► AD API ──(LDAP bind)──► AD
     ◄──────────── JWT (RS256) + grupos ────────┘   │
 Aplicação valida o JWT localmente                  └──► PostgreSQL (aplicações clientes + chaves JWT)
 com /.well-known/jwks.json
```

## Endpoints

Toda aplicação tem um **nível de acesso** (`access_level`), definido no cadastro:

- **`basic`** (padrão): só os endpoints básicos. O login devolve apenas `login`, `email` e `is_active`, e o token carrega só login e e-mail.
- **`full`**: também os endpoints completos (dados e grupos do usuário, introspect, authorize e diretório).

| Método | Rota | Quem pode | Descrição |
|---|---|---|---|
| POST | `/api/v1/auth/basic/login` | qualquer aplicação | Valida usuário/senha no AD e devolve JWT + `login`, `email`, `is_active` |
| POST | `/api/v1/auth/basic/introspect` | qualquer aplicação | Diz se um token é válido (resposta resumida: login, e-mail, expiração) |
| POST | `/api/v1/auth/login` | `full` | Valida usuário/senha no AD e devolve JWT + dados completos + grupos |
| POST | `/api/v1/auth/introspect` | `full` | Diz se um token é válido e devolve todos os claims |
| POST | `/api/v1/auth/authorize` | `full` | Verifica se o dono do token está nos grupos informados (`any`/`all`) |
| GET | `/api/v1/users/{login ou e-mail}` | `full` + `allow_directory_lookup` | Dados/grupos atuais de um usuário (conta de serviço) |
| GET | `/api/v1/groups/{group}/members` | `full` + `allow_directory_lookup` | Membros de um grupo (só dentro dos `group_prefixes`) |
| GET | `/.well-known/jwks.json` | público | Chave pública para validar os tokens |
| GET | `/health` / `/health/ready` | público | Liveness / readiness (testa bind no AD) |

Todas as rotas `/api/v1/*` exigem o header `X-API-Key`. Uma aplicação `basic` que chama um
endpoint completo recebe `403`.

### Login por login ou e-mail

O campo `username` aceita:

- o login do AD: `nome.sobrenome` (ou `DOMINIO\nome.sobrenome`);
- o **e-mail cadastrado no AD**, por exemplo `nome.sobrenome@example.com`. A API procura o usuário pelo atributo `mail` (ou pelo `userPrincipalName`). Nenhum domínio fica fixo no código: vale o que estiver cadastrado no AD.

O login por e-mail usa a conta de serviço (`AD_USER`/`AD_PASSWORD`) para localizar o usuário.
Se o mesmo e-mail estiver em mais de um usuário, o login é recusado.

### Documentação (`/docs`, `/redoc`, `/openapi.json`)

Não é pública: exige **usuário e senha** (HTTP Basic). Cada aplicação pode ter a sua credencial,
definida no cadastro (`./admin.sh add` ou `edit`). A API key **não** abre a documentação.
Uma aplicação `basic` só enxerga os endpoints básicos (e os de saúde) na documentação.

## Aplicações clientes (tabela `clients`)

Cada aplicação tem um `client_id` e uma API key. Só o SHA-256 da chave fica no banco.
Cadastre e altere pelo `./admin.sh` (`add` / `edit`), que gera a key e os hashes.
A API consulta o banco a cada requisição: **toda alteração vale na hora, sem restart**.

| Campo | Efeito |
|---|---|
| `access_level` | `basic` (padrão) ou `full`. Veja [Endpoints](#endpoints). |
| `group_prefixes` | (`full`) Só grupos com esses prefixos vão para a resposta e o token daquela aplicação (ex.: `GRP_APP_`). Vazio = todos. |
| `required_groups` | Login só é aceito se o usuário estiver em **pelo menos um** desses grupos (senão `403`). Vale para os dois níveis. Vazio = qualquer usuário ativo do AD. |
| `allow_directory_lookup` | (`full`) Libera `/users` e `/groups`. |
| `docs_username` / `docs_password_hash` | Credencial da documentação. Sem eles, a aplicação não abre `/docs`. A senha é guardada com scrypt. |

O token sai com `aud = client_id`: um token emitido para uma aplicação não é aceito por outra.

## Exemplo de uso

Nível básico (qualquer aplicação):

```bash
curl -X POST http://localhost:8282/api/v1/auth/basic/login \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"username": "nome.sobrenome@example.com", "password": "..."}'
```

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "user": { "login": "nome.sobrenome", "email": "nome.sobrenome@example.com", "is_active": true }
}
```

Nível completo (`access_level=full`):

```bash
curl -X POST http://localhost:8282/api/v1/auth/login \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"username": "nome.sobrenome", "password": "..."}'
```

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "user": {
    "username": "nome.sobrenome",
    "first_name": "Nome", "last_name": "Sobrenome",
    "email": "nome.sobrenome@example.com",
    "password_expires_in_days": 12,
    "groups": ["GRP_APP_USER", "GRP_APP_SETUP"]
  }
}
```

Validando o token localmente em Python (sem chamar a API):

```python
import jwt
jwks = jwt.PyJWKClient("http://<servidor>:8282/.well-known/jwks.json")
key = jwks.get_signing_key_from_jwt(token)
claims = jwt.decode(token, key, algorithms=["RS256"], audience="<client_id>", issuer="active-directory-api")
claims["groups"]
```

O mapeamento grupo → permissão (ex.: `GRP_APP_ADMIN` → `admin`) continua
em cada aplicação; esta API só entrega os grupos do AD.

## Testando com o Postman

Collection pronta em [`docs/postman/active-directory-api.postman_collection.json`](docs/postman/active-directory-api.postman_collection.json)
com todos os endpoints. No Postman: **Import** → arraste o arquivo.

**1. Variáveis** (clique na collection → aba **Variables**):

| Variável | Valor |
|---|---|
| `baseUrl` | `http://<servidor>:8282` (local: `http://localhost:8282`) |
| `apiKey` | API key da aplicação (gerada pelo `./admin.sh add`) |
| `username` / `password` | credenciais do AD (`username` aceita login ou e-mail) |
| `group` | grupo usado nos testes de autorização/diretório (padrão `GRP_APP_ADMIN`) |
| `token` | preenchida automaticamente pelo Login |

> Coloque `apiKey` e `password` só em **Current value**: esse valor fica apenas na sua máquina
> e não vai junto ao exportar/compartilhar a collection.

A API key é enviada no header `X-API-Key` em todas as requisições (aba **Authorization** da
collection); as de saúde usam *No Auth*.

**2. Requisições**

| Pasta | Requisição | Esperado |
|---|---|---|
| Saúde | Health | `{"status":"ok"}` |
| | Ready (conexão com o AD) | `ok` = a API alcança o AD com a conta de serviço |
| | JWKS | chave pública dos tokens |
| Autenticação básica | **1. Login básico** | token + `login`, `email`, `is_active`; **salva o token em `{{token}}`** |
| | 2. Introspect básico | `"active": true`, login, e-mail e expiração |
| Autenticação completa (`full`) | **1. Login** | token + dados + grupos; **salva o token em `{{token}}`** |
| | 2. Introspect | `"active": true` + todos os claims |
| | 3. Authorize (any / all) | se o usuário está nos grupos informados |
| Diretório (`full` + `allow_directory_lookup`) | Usuário / Membros do grupo | dados atuais do usuário / membros do grupo |
| Cenários de erro | sem API key / senha errada | `401` |
| | endpoint completo com aplicação básica | `403` |

Rode um **Login** primeiro: as requisições seguintes usam o token salvo. Com uma aplicação
`basic`, use só a pasta *Autenticação básica*.

**3. Problemas comuns**

| Resposta | Causa |
|---|---|
| `401 API key ausente ou inválida` | `apiKey` vazia/errada ou salva só em *Initial value* |
| `401 Usuário ou senha inválidos` | credencial errada; o motivo real (senha expirada, conta bloqueada...) sai no log: `docker service logs active-directory-api_api` |
| `403 Aplicação com acesso básico` | aplicação `basic` chamando endpoint completo: use `/api/v1/auth/basic/*` ou mude para `full` com `./admin.sh edit` |
| `403` no Login | a aplicação tem `required_groups` e o usuário não está em nenhum |
| `groups` vazio | nenhum grupo do usuário casa com os `group_prefixes` da aplicação |
| `503` | a API não alcança o AD: conferir `AD_SERVER` no `variables.env` |

Alternativa sem Postman: `http://<servidor>:8282/docs`. O navegador pede o **usuário e senha da
documentação** da aplicação; depois, **Authorize** → cole a API key para testar as requisições.

## Banco de dados (PostgreSQL)

Aplicações clientes e chaves JWT ficam no PostgreSQL, no schema `DATABASE_SCHEMA` (padrão `active_directory_api`).
Variáveis: `DATABASE_HOST`, `DATABASE_USER`, `DATABASE_PASSWORD` (criptografada com `APP_MASTER_KEY`)...

| Tabela | Conteúdo |
|---|---|
| `clients` | aplicações: `client_id`, nível de acesso, grupos, hash da API key, credencial da documentação |
| `signing_keys` | chaves RSA que assinam os JWT, **criptografadas com `APP_MASTER_KEY`**; só uma ativa |
| `alembic_version` | controle das migrations |

- **Não precisa criar tabelas nem chave**: ao subir, o container roda `python -m app.bootstrap`, que
  cria o schema, aplica as migrations e gera a primeira chave JWT. Instâncias subindo juntas não
  conflitam (advisory lock no Postgres).
- O usuário do banco precisa poder criar o schema/tabelas na primeira subida (ou crie o schema antes
  e dê permissão nele).
- **`APP_MASTER_KEY` é obrigatória e não pode mudar** depois de criada: a chave JWT no banco só abre com ela.
- **Troca de chave JWT sem derrubar ninguém**: `rotate-jwt` cria uma chave nova; a anterior continua
  no JWKS e validando os tokens já emitidos até eles expirarem (`JWT_EXPIRES_MINUTES`).
- Nova migration (desenvolvimento): `alembic revision -m "descricao"` e editar o arquivo em
  `app/db/migrations/versions/`.

## Produção (Docker Swarm)

No manager, numa pasta com `docker-project.yml`, `variables.env`, `start.sh`, `stop.sh` e `admin.sh`.

| O quê | Onde fica | Como muda | Aplica |
|---|---|---|---|
| AD, banco, `APP_MASTER_KEY`, JWT_* | `variables.env` (manager) | editar o arquivo | `./start.sh` |
| Aplicações clientes | PostgreSQL (`clients`) | `./admin.sh add/edit/rotate/remove` | na hora |
| Chave de assinatura JWT | PostgreSQL (`signing_keys`) | `./admin.sh rotate-jwt` | em até 30s |

### Primeira instalação

```bash
cp variables.env.example variables.env
./admin.sh encrypt     # gera APP_MASTER_KEY + AD_PASSWORD -> colar no variables.env
./admin.sh encrypt     # de novo, informando a mesma APP_MASTER_KEY, variável DATABASE_PASSWORD
vi variables.env                 # substituir os <...>: AD_SERVER, AD_USER, DATABASE_HOST...
docker network create -d overlay backend   # se a rede ainda não existir (ou SWARM_NETWORK=<rede existente>)
./admin.sh init        # cria tabelas + chave JWT e cadastra a 1ª aplicação (mostra a API key)
./start.sh
```

### Dia a dia

```bash
./start.sh                      # sobe/atualiza a stack (também após alterar o variables.env)
./stop.sh                       # docker stack rm; aplicações e chave JWT continuam no banco

./admin.sh            # menu
./admin.sh add        # nova aplicação: nível de acesso, grupos, usuário/senha da documentação (credenciais aparecem UMA vez)
./admin.sh edit       # alterar aplicação existente (nível de acesso, grupos, documentação)
./admin.sh list
./admin.sh rotate     # nova API key para uma aplicação
./admin.sh remove
./admin.sh rotate-jwt # nova chave de assinatura (tokens já emitidos continuam valendo até expirar)
./admin.sh keys       # chaves JWT: ativa, aposentadas
```

O script roda o CLI dentro da imagem da API com o `variables.env`; precisa só de Docker e de acesso
ao banco a partir da máquina onde roda. Variáveis opcionais: `ENV_FILE`, `IMAGE` ou `REGISTRY`/`IMAGE_TAG`,
`NETWORK` (rede Docker para alcançar o banco; padrão `host`).

Variáveis do `docker-project.yml` (no ambiente de quem roda o `./start.sh`): `REGISTRY` (padrão
`registry.example.com`), `IMAGE_TAG`, `APP_PORT` (padrão `8282`) e `SWARM_NETWORK` (rede overlay externa, padrão `backend`).

## Desenvolvimento local

`docker-compose.local.yml` sobe a API + um PostgreSQL (dados no volume `pgdata`, acessível em
`localhost:15432`; senha em `POSTGRES_PASSWORD`, padrão `change-me-local`). As variáveis vêm de `config/app.env` (modelo: `config/app.env.example`).

```bash
docker compose -f docker-compose.local.yml up -d --build
docker compose -f docker-compose.local.yml run --rm api python -m app.cli    # administração

# Sem Docker (usa o Postgres do compose em localhost:15432, ver config/app.env.example)
poetry install
poetry run python -m app.bootstrap
poetry run uvicorn app.main:app --reload
poetry run pytest                # testes usam SQLite em memória, não precisam do Postgres
```

## Segurança

- Use `AD_SSL=true` com `AD_CERTS` em produção: sem LDAPS a senha trafega em texto até o AD.
- Exponha a API apenas via HTTPS (atrás do proxy/ingress).
- Senha vazia é rejeitada antes do bind (no AD, simple bind com senha vazia pode ser aceito como anônimo).
- Entradas do usuário são escapadas antes de entrar em filtros LDAP.
- Não há rate limit na API; o bloqueio por tentativas fica a cargo da política de lockout do AD.
- No banco: API keys só como SHA-256, senhas da documentação com scrypt e chave JWT criptografada
  com `APP_MASTER_KEY`. Quem lê o banco sem a `APP_MASTER_KEY` não consegue emitir tokens.
