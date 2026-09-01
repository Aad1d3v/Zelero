# Zelero — production container
#
# Build:  docker build -t zelero .
# Run:    docker run -p 8080:8080 \
#           -e SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
#           -e GROQ_API_KEY=<your-key> \
#           -e SESSION_COOKIE_SECURE=1 \
#           -v zelero-data:/var/data \
#           -e ZELERO_DB_PATH=/var/data/codehelper.db \
#           zelero
#
# GROQ_API_KEY and SECRET_KEY are read from the environment at runtime —
# never bake them into the image.

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Install dependencies first so Docker's layer cache skips this step on code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code (index.html, style.css, app.py). .dockerignore keeps secrets,
# the SQLite database, and local artifacts out of the build context.
COPY app.py index.html style.css ./

# Run as an unprivileged user (the base image defaults to root).
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# Persistent state (SQLite DB) lives on a volume when provided:
#   docker run -v zelero-data:/var/data -e ZELERO_DB_PATH=/var/data/codehelper.db ...
# Without a volume the DB is ephemeral and resets when the container is removed.

EXPOSE 8080

# Production WSGI server — never the Flask dev server. PORT is env-driven so
# the same image works on any host (Render, Fly, ECS, local Docker…).
# Shell form so ${PORT} is expanded from the environment at container start.
CMD ["sh", "-c", "waitress-serve --host=0.0.0.0 --port=${PORT} app:app"]

# Docker-native healthcheck (platforms without a separate health probe):
# /api/health returns 200 when the app + DB are up, 503 when the DB is down.
# curl is not in python:3.13-slim, so probe with waitress's own urllib.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','8080')+'/api/health', timeout=4).status==200 else 1)"]
