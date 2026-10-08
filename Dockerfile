# --- Estágio de Build ---
FROM python:3.13-slim AS builder

ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    PATH_PROJECTS="/opt/Projects"

ENV PATH="${POETRY_HOME}/bin:$PATH"

RUN apt-get update && apt-get install --no-install-recommends -y curl \
    && curl -sSL https://install.python-poetry.org | python3 -

WORKDIR ${PATH_PROJECTS}

COPY poetry.lock* pyproject.toml ./

# --only main: não instala pytest/httpx na imagem final
RUN poetry install --no-root --only main

# --- Estágio Final ---
FROM python:3.13-slim AS final

ARG PATH_PROJECTS="/opt/Projects"
ENV PATH_PROJECTS=${PATH_PROJECTS}
WORKDIR ${PATH_PROJECTS}

RUN useradd --system --no-create-home --uid 10001 appuser

COPY --from=builder ${PATH_PROJECTS}/.venv ./.venv
ENV PATH="${PATH_PROJECTS}/.venv/bin:$PATH"

COPY app ./app

# Configuração entra em runtime, nunca na imagem: variáveis do variables.env (env_file);
# aplicações clientes e chave JWT ficam no PostgreSQL

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

# Prepara o banco (migrations + 1ª chave JWT) e só então sobe a API. Se o banco não responder,
# o container sai com erro e o Swarm tenta de novo (restart_policy).
CMD ["sh", "-c", "python -m app.bootstrap && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 --proxy-headers"]
