# CodeFense Platform API

Production-grade REST API for the CodeFense SaaS platform — package security analytics, supply-chain monitoring, and vulnerability intelligence for engineering teams.

## Overview

CodeFense Platform API powers:
- **Package Analysis** — deep static and dynamic analysis of npm, PyPI, and RubyGems packages
- **Supply-Chain Monitoring** — continuous monitoring of your dependency graph against threat feeds
- **Policy Engine** — configurable organisational policies with blocking rules and audit trails
- **Reporting** — on-demand and scheduled PDF/JSON reports with SARIF export

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌────────────────┐
│   Load Balancer  │────▶│  Platform API    │────▶│  PostgreSQL 15 │
│   (ALB / nginx)  │     │  (Node/Express)  │     │  (RDS)         │
└──────────────────┘     └────────┬─────────┘     └────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             ┌──────────┐  ┌──────────┐  ┌──────────┐
             │  Redis   │  │   S3     │  │  SQS     │
             │  Cache   │  │ Storage  │  │  Queue   │
             └──────────┘  └──────────┘  └──────────┘
```

## Getting Started

### Prerequisites

- Node.js >= 18
- PostgreSQL 15
- Redis 7

### Installation

```bash
npm install
cp .env.example .env
# Edit .env with your credentials
npm run migration:run
npm run seed
npm run dev
```

### Running Tests

```bash
npm test
```

### API Documentation

Swagger UI is available at `/api/docs` when `NODE_ENV=development`.

## Environment Variables

See `.env.example` for the full list. Critical variables:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `JWT_SECRET` | Secret for signing JWTs |
| `S3_BUCKET` | S3 bucket for report storage |

## Deployment

Docker images are built and pushed to ECR on every merge to `main` via GitHub Actions.

```bash
docker build -t codefense-api .
docker run -p 3000:3000 --env-file .env codefense-api
```

## Contributing

1. Branch from `main`
2. Follow the existing patterns in `src/`
3. Add unit tests for any new service methods
4. Ensure `npm run lint` and `npm test` pass before opening a PR
