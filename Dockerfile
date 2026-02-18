# Trivy container targets — Dockerfile anti-patterns
# WARNING: Intentionally insecure for scanner testing

FROM ubuntu:20.04

# No pinned version for apt packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Hardcoded secret in ENV
ENV DATABASE_PASSWORD=SuperSecret123
ENV API_KEY=test-api-key-not-for-production

# Running as root (no USER directive)
WORKDIR /app
COPY . .

# Using ADD instead of COPY for local files
ADD src/ /app/src/

EXPOSE 8080

CMD ["python3", "src/app.py"]
