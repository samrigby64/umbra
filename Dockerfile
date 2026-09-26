# Umbra application image — runs the crawler worker, the API, and CLI tasks.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UMBRA_LOG_LEVEL=INFO

WORKDIR /app

# Copy only what the build needs first (better layer caching).
COPY pyproject.toml README.md ./
COPY src ./src

# API extra (fastapi/uvicorn) + embeddings extra (the real semantic embedder).
# [embeddings] is not optional in practice: the default embedder_kind is "local",
# and without it the image falls back to lexical hashing search *silently* — the
# service still starts and still returns results, they are just far worse. Add
# [llm] here as well if you want LLM enrichment.
RUN pip install ".[api,embeddings]"

# Bake the model into the image so the first search doesn't pay a cold download
# (and so an air-gapped or egress-filtered deployment works at all).
RUN python -c "from fastembed import TextEmbedding; TextEmbedding(model_name='BAAI/bge-small-en-v1.5')"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 umbra
USER umbra

# `umbra <command>` — compose overrides this per service (serve / worker / init-db).
ENTRYPOINT ["umbra"]
CMD ["--help"]
