# SignalHound Specification

SignalHound is an authorized external reconnaissance and exposure-management application.

The current implementation covers **Epic 1: Foundation**, **Epic 2: Scope Management and Scope Enforcement**, **Epic 3: Asset Inventory and Historization**, **Epic 4: Scanner Adapter Framework**, **Epic 5: External Discovery**, **Epic 6: Finding Normalization and Management**, **Epic 7: Change Detection**, and **Epic 8: Basic Security Dashboard / UI**.

## Epic 1 Deliverables

- Repository / monorepo structure
- FastAPI backend
- PostgreSQL integration
- SQLAlchemy configuration
- Alembic migration framework
- Redis
- Celery worker
- Docker Compose development environment
- Environment configuration
- Structured application logging
- `GET /health`
- pytest setup
- `.env.example`
- `.gitignore`
- README with reproducible development commands

## Epic 2 Deliverables

- Organization records as scope owners
- Explicit external scope records
- Scope target types: `DOMAIN`, `HOSTNAME`, `IP`, `CIDR`
- MVP scan zone: `EXTERNAL`
- Scanner-independent scope validation
- Audit events for scope creation, change, soft deletion, and validation decisions
- API endpoints under `/api/v1`

## Epic 3 Deliverables

- Asset records scoped to organizations
- Optional scope linkage for authorized known assets
- Unscoped discovered/unverified assets
- Asset types: `DOMAIN`, `SUBDOMAIN`, `IP`, `HOST`
- Service records attached to assets
- Service protocols: `TCP`, `UDP`
- `first_seen` and `last_seen` tracking
- Asset and service observation history tables
- API endpoints for inventory and observation history
- Tests proving repeated observations preserve history instead of overwriting it

## Epic 4 Deliverables

- Scanner adapter base contract
- Adapter registry
- Placeholder registrations for `nmap`, `amass`, and `nuclei`
- Scanner job table with lifecycle status and prepared configuration
- Raw output and normalized result storage fields for future execution epics
- Scope-gated scanner job preparation API
- Audit events for prepared and rejected scanner jobs
- Tests proving out-of-scope targets do not create scanner jobs

## Epic 5 Deliverables

- Scanner execution gate controlled by environment configuration
- Shell-free external tool execution wrapper with timeout support
- Nmap command preparation, XML parsing, and service normalization
- Amass command preparation, JSONL parsing, and asset normalization
- Scanner job execution endpoint
- Scanner started/completed/failed audit events
- Result import into asset and service inventory with observation history
- Out-of-scope discoveries recorded as unscoped/unverified inventory instead of authorized targets
- Tests proving disabled execution, scoped result import, and out-of-scope rejection behavior

## Epic 6 Deliverables

- Finding records attached to assets and optionally services
- Finding severities: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Finding lifecycle: `NEW`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`
- Finding observation history
- Explicit audited finding status changes
- Manual finding create/observe API
- Nuclei JSONL parsing and finding normalization
- Scanner result import into finding inventory
- Tests proving finding history, lifecycle updates, and scanner finding import

## Epic 7 Deliverables

- Persisted change sets for point-in-time comparisons
- Change events for assets, services, and findings
- Added and removed object detection based on existing historized inventory fields
- Change summaries grouped by entity type and change type
- API endpoints under `/api/v1/change-sets`
- Audit events for change-set creation
- Tests proving asset, service, and finding changes are detected

## Epic 8 Deliverables

- React dashboard UI served as a Docker Compose service
- Backend CORS configuration for the dashboard origin
- Organization selection and creation
- Overview metrics for implemented MVP data
- Scope creation and listing
- Asset observation and inventory views
- Finding creation and listing
- Scanner job preparation and run action
- Change-set comparison and listing
- Reproducible frontend build commands in README

## Security Boundary

SignalHound is intended only for authorized security assessments. The current implementation performs no scanning, exploitation, credential attacks, brute force functionality, payload deployment, or destructive testing.
