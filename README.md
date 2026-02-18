# Task Dashboard

A lightweight Flask API for managing team tasks.
Built as an internal tool for the DevOps team.

## Quick Start

```bash
pip install -r requirements.txt
python src/app.py
```

## API Endpoints

- `GET /tasks` — list all tasks
- `POST /tasks` — create a new task
- `GET /health` — health check
- `GET /admin/run` — run maintenance commands (admin only)
- `GET /admin/verify` — verify data integrity

## Deployment

```bash
docker build -t task-dashboard .
docker run -p 8080:8080 task-dashboard
```

## CI

Pull requests are automatically tested via GitHub Actions.
