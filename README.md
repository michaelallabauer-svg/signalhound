# SignalHound

SignalHound is an authorized external reconnaissance and exposure-management platform. This repository currently implements **Epic 1: Foundation**, **Epic 2: Scope Management and Scope Enforcement**, **Epic 3: Asset Inventory and Historization**, and **Epic 4: Scanner Adapter Framework**.

No active scanner execution, finding workflows, exploitation features, change detection, or frontend are implemented yet.

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
- `backend/app/services/scope_validation.py` enforces scope before any future scanner can receive a target.
- `backend/app/api/assets.py` and `backend/app/api/services.py` expose inventory and observation history APIs.
- `backend/app/scanners/` contains the scanner adapter contract and registry.
- `backend/app/api/scanner_jobs.py` prepares scanner jobs only after scope validation.
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

## Scope Management API

Create an organization:

```bash
curl -X POST http://localhost:8010/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name":"Example Corp"}'
```

Create an external scope:

```bash
curl -X POST http://localhost:8010/api/v1/scopes \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"name":"Example domain","target_type":"DOMAIN","target":"example.com"}'
```

Validate a target before scanning:

```bash
curl -X POST http://localhost:8010/api/v1/scopes/validate \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"target":"www.example.com"}'
```

Expected allowed response:

```json
{
  "target": "www.example.com",
  "normalized_target": "www.example.com",
  "allowed": true,
  "scope_id": 1,
  "reason": "target matched active scope"
}
```

Scope target behavior:

- `DOMAIN` authorizes the domain and its subdomains.
- `HOSTNAME` authorizes exactly that hostname.
- `IP` authorizes exactly that IP address.
- `CIDR` authorizes IP addresses inside the range.

## Asset Inventory API

Record or refresh an asset observation:

```bash
curl -X POST http://localhost:8010/api/v1/assets \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"scope_id":1,"asset_type":"SUBDOMAIN","value":"www.example.com","source":"manual"}'
```

List assets:

```bash
curl http://localhost:8010/api/v1/assets?organization_id=1
```

View asset observation history:

```bash
curl http://localhost:8010/api/v1/assets/1/observations
```

Record or refresh a service observation:

```bash
curl -X POST http://localhost:8010/api/v1/services \
  -H "Content-Type: application/json" \
  -d '{"asset_id":1,"protocol":"TCP","port":443,"name":"https","source":"manual"}'
```

View service observation history:

```bash
curl http://localhost:8010/api/v1/services/1/observations
```

Historization behavior:

- Re-observing an existing asset updates `last_seen` and creates a new `asset_observations` row.
- Re-observing an existing service updates `last_seen` and creates a new `service_observations` row.
- `first_seen` is preserved.
- Assets may be recorded without a `scope_id` as discovered/unverified inventory, but scoped assets must pass scope validation.
- No inactive records or historical observations are deleted when an asset or service is marked inactive.

## Scanner Adapter Framework API

List registered scanner adapters:

```bash
curl http://localhost:8010/api/v1/scanner-adapters
```

Prepare a scanner job:

```bash
curl -X POST http://localhost:8010/api/v1/scanner-jobs \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"scope_id":1,"adapter_name":"nmap","target":"www.example.com"}'
```

Important Epic 4 behavior:

- Targets are scope-validated before any scanner adapter receives them.
- Out-of-scope targets are rejected and audited.
- Registered adapters: `nmap`, `amass`, `nuclei`.
- Adapter execution is intentionally not implemented yet.
- Scanner jobs are stored as `PREPARED` with prepared config, raw output fields, normalized result fields, and lifecycle timestamps for later epics.

## Implemented Scope

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
- Organization management
- Scope management
- Scope validation
- Scope audit events
- Asset inventory
- Service inventory
- Asset and service observation history
- Scanner adapter contract and registry
- Scope-gated scanner job preparation

Deferred to later epics:

- External discovery
- Finding management
- Change detection
- Frontend
