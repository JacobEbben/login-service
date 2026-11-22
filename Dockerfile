# Login Service - production image.
#   docker build -t login-service .
#   docker compose up -d --build        (local, see compose.yaml)
# Settings come from the environment at run time; .env is never copied in.
# /app/data (SQLite database, token-signing keys, generated secret key) must be a volume.

# Same digest-pinned base as ah-dashboard. To update: docker pull python:3.12-slim,
# then put the new digest from `docker image inspect` here (and in .github/workflows/ci.yml).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.lock .
RUN pip install --require-hashes --no-deps -r requirements.lock

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY login_service/ login_service/
COPY serve.py ./

# Code: readable, not writable. data/: owned by the app user.
RUN chmod -R u=rwX,go=rX /app/login_service /app/serve.py \
 && mkdir -p /app/data && chown app:app /app/data && chmod 700 /app/data

USER app

ENV APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    THREADS=8 \
    DATA_DIR=/app/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8080'), timeout=4)" || exit 1

# One process: rate limits and lockouts live in it.
CMD ["python", "serve.py"]
