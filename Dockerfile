FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port
EXPOSE 5000

# Run as root (security anti-pattern for container scanners to flag)
USER root

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "src.app:app"]
