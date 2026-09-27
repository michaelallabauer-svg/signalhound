# SignalHound

SignalHound is an authorized external reconnaissance and exposure-management platform. This repository currently implements **Epic 1: Foundation**, **Epic 2: Scope Management and Scope Enforcement**, **Epic 3: Asset Inventory and Historization**, **Epic 4: Scanner Adapter Framework**, **Epic 5: External Discovery**, **Epic 6: Finding Normalization and Management**, **Epic 7: Change Detection**, and **Epic 8: Basic Security Dashboard / UI**.

No exploitation features are implemented.

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
- `backend/app/api/findings.py` exposes normalized finding and lifecycle APIs.
- `backend/app/api/changes.py` exposes persisted point-in-time change comparisons.
- `frontend/` contains the React dashboard UI for the implemented MVP workflows.
- `backend/app/scanners/` contains the scanner adapter contract and registry.
- `backend/app/api/scanner_jobs.py` prepares scanner jobs only after scope validation.
- `backend/alembic/` contains the Alembic migration framework.
- `docker-compose.yml` starts PostgreSQL, Redis, FastAPI, Celery, and the frontend.

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
- `SCANNER_EXECUTION_ENABLED`
- `SCANNER_TIMEOUT_SECONDS`
- `CORS_ORIGINS`
- `VITE_API_BASE_URL`
- `AMASS_VERSION`
- `NUCLEI_VERSION`

Never commit real credentials.

## Start the Application

```bash
docker compose up --build
```

FastAPI will be available at:

```text
http://localhost:8010
```

The dashboard UI will be available at:

```text
http://localhost:8011
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

Frontend build:

```bash
cd frontend
npm install
npm run build
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
cd frontend && npm run build
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f frontend
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
- Scanner jobs are stored as `PREPARED` with prepared config, raw output fields, normalized result fields, and lifecycle timestamps.

## External Discovery

Scanner execution is disabled by default. Enable it only for authorized assessments:

```bash
SCANNER_EXECUTION_ENABLED=true docker compose up --build
```

Run a prepared scanner job:

```bash
curl -X POST http://localhost:8010/api/v1/scanner-jobs/1/run
```

Epic 5 behavior:

- `nmap` execution uses a shell-free subprocess command plan: `nmap -oX - -sV <target>`.
- `amass` execution uses JSONL output: `amass enum -json - -d <target>`.
- The backend and worker Docker images include `nmap`, OWASP Amass, and ProjectDiscovery Nuclei.
- Results are parsed and normalized into assets/services.
- In-scope discovered assets are linked to the scope and marked known.
- Out-of-scope discovered assets may be recorded without `scope_id` as discovered/unverified inventory.
- Services are attached to normalized assets and historized.
- `nuclei` normalizes JSONL findings into the finding inventory.

## Finding Management API

Create or refresh a finding observation:

```bash
curl -X POST http://localhost:8010/api/v1/findings \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"asset_id":1,"title":"Missing security header","severity":"LOW","source":"manual"}'
```

List findings:

```bash
curl http://localhost:8010/api/v1/findings?organization_id=1
```

Change finding status:

```bash
curl -X PATCH http://localhost:8010/api/v1/findings/1/status \
  -H "Content-Type: application/json" \
  -d '{"status":"ACKNOWLEDGED","remediation":"Track with owner"}'
```

View finding observation history:

```bash
curl http://localhost:8010/api/v1/findings/1/observations
```

Finding lifecycle:

- `NEW`
- `ACKNOWLEDGED`
- `IN_PROGRESS`
- `RESOLVED`
- `ACCEPTED_RISK`
- `FALSE_POSITIVE`

Finding behavior:

- Re-observing an existing finding updates `last_seen` and creates a `finding_observations` row.
- `first_seen` and the current lifecycle `status` are preserved during re-observation.
- Status changes are explicit API actions and are auditable.
- Nuclei findings are imported through scanner jobs when scanner execution is enabled.

Scanner tooling:

- `nmap` is installed from the Debian package repository.
- Amass is installed from the pinned `AMASS_VERSION` GitHub release.
- Nuclei is installed from the pinned `NUCLEI_VERSION` GitHub release.
- Scanner execution remains disabled until `SCANNER_EXECUTION_ENABLED=true` is set.

## Change Detection API

Create a persisted comparison between two points in time:

```bash
curl -X POST http://localhost:8010/api/v1/change-sets/compare \
  -H "Content-Type: application/json" \
  -d '{"organization_id":1,"baseline_at":"2026-01-01T12:00:00Z","comparison_at":"2026-01-02T12:00:00Z"}'
```

List stored comparisons:

```bash
curl http://localhost:8010/api/v1/change-sets?organization_id=1
```

View a comparison with events:

```bash
curl http://localhost:8010/api/v1/change-sets/1
```

View only events:

```bash
curl http://localhost:8010/api/v1/change-sets/1/events
```

Epic 7 behavior:

- Change sets store the requested baseline and comparison timestamps.
- Change events are stored for assets, services, and findings.
- Added and removed objects are detected from the existing historized inventory fields.
- Findings are considered removed when they are terminal at the comparison point (`RESOLVED` or `FALSE_POSITIVE`).
- Change-set creation is audited.
- No management scoring is implemented.

## Dashboard UI

Open the dashboard:

```text
http://localhost:8011
```

Epic 8 behavior:

- Organization selection and creation.
- Overview metrics for active scopes, assets, services, findings, scanner jobs, backend health, and latest change count.
- Scope creation and scope table.
- Asset observation form and inventory tables.
- Finding creation and finding table.
- Scanner job preparation and run action.
- Change-set comparison form and change-set table.
- Frontend is served by Docker Compose through the `frontend` service.
- Browser API access is enabled through backend CORS configuration.

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
- Scope-gated external discovery execution for Nmap and Amass
- Discovery result import into asset and service history
- Finding inventory and lifecycle management
- Nuclei finding normalization
- Finding observation history
- Point-in-time change-set comparisons
- Asset, service, and finding change events
- Change detection audit events
- Basic security dashboard UI
