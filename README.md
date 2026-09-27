# SignalHound

SignalHound is an authorized external reconnaissance and exposure-management platform. This repository currently implements **Epic 1: Foundation** only.

No scanner integrations, scope management, asset inventory, finding workflows, exploitation features, or frontend are implemented in this epic.

## Prerequisites

- Python 3.12+
- Docker and Docker Compose
- PostgreSQL client tools are useful for local debugging

## Architecture Overview

- `backend/app/main.py` creates the FastAPI application.
- `backend/app/api/health.py` exposes `GET /health`.
- `backend/app/core/config.py` loads environment-based configuration.
- `backend/app/core/database.py` owns SQLAlchemy engine/session setup.
- `backend/app/core/logging.py` configures JSON application logging.
- `backend/app/workers/celery_app.py` configures the Celery worker.
- `backend/alembic/` contains the Alembic migration framework.
- `docker-compose.yml` starts PostgreSQL, Redis, FastAPI, and Celery.

The health endpoint is intentionally small in Epic 1 but is structured so dependency checks can be added later without changing the API boundary.

## Environment

Copy the example file when you want local overrides:

```bash
cp .env.example .env
```

Important variables:

- `APP_NAME`
- `ENVIRONMENT`
- `LOG_LEVEL`
- `DATABASE_URL`
- `REDIS_URL`

Never commit real credentials.

## Start the Application

```bash
docker compose up --build
```

FastAPI will be available at:

```text
http://localhost:8010
```

Health check:

```bash
curl http://localhost:8010/health
```

Expected response:

```json
{"status":"ok"}
```

## Stop the Application

```bash
docker compose down
```

To also remove local database data:

```bash
docker compose down -v
```

## Run Migrations

From the repository root:

```bash
docker compose run --rm backend alembic upgrade head
```

For local execution:

```bash
cd backend
DATABASE_URL=postgresql+psycopg://signalhound:signalhound@localhost:5432/signalhound alembic upgrade head
```

## Run Tests

Local:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Docker:

```bash
docker compose run --rm backend pytest
```

## Start the Celery Worker

Docker Compose starts the worker by default. To run it manually:

```bash
docker compose run --rm worker celery -A app.workers.celery_app.celery_app worker --loglevel=INFO
```

## Important Development Commands

```bash
docker compose up --build
docker compose run --rm backend alembic upgrade head
docker compose run --rm backend pytest
docker compose logs -f backend
docker compose logs -f worker
docker compose down
```

## Epic 1 Scope

Implemented:

- Repository structure
- FastAPI backend
- PostgreSQL configuration
- SQLAlchemy setup
- Alembic framework
- Redis configuration
- Celery worker configuration
- Docker Compose development environment
- Environment configuration
- JSON logging
- `GET /health`
- pytest setup

Deferred to later epics:

- Scope management
- Scope enforcement
- Asset inventory
- Scanner adapters
- External discovery
- Finding management
- Change detection
- Frontend
