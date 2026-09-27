# SignalHound Specification

SignalHound is an authorized external reconnaissance and exposure-management application.

The current implementation covers **Epic 1: Foundation**, **Epic 2: Scope Management and Scope Enforcement**, **Epic 3: Asset Inventory and Historization**, **Epic 4: Scanner Adapter Framework**, **Epic 5: External Discovery**, **Epic 6: Finding Normalization and Management**, **Epic 7: Change Detection**, **Epic 8: Basic Security Dashboard / UI**, **Epic 9: Scan Automation Foundation**, **Epic 10: Assessment Run Visibility**, and **Epic 11: Internal IT Recon Foundation**.

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

## Epic 9 Deliverables

- Assessment run model for grouped scan execution
- Static external scan profiles
- External quick profile: Nmap and Nuclei
- External discovery profile: Amass, Nmap, and Nuclei
- Scope enforcement before any assessment jobs are prepared
- Assessment API for profile listing, run creation, and run listing
- Celery task for sequential scanner-job execution inside an assessment
- Scanner jobs linked back to their assessment run
- Basic assessment run summary counts
- Dashboard control for starting an assessment from a selected scope and target

## Epic 10 Deliverables

- Assessment detail API including linked scanner jobs
- Dashboard selection of previous assessment runs
- Per-assessment job status, error, and output visibility
- Automatic dashboard refresh while assessment runs are queued or running
- Stored scanner output can be opened from the assessment detail view

## Epic 11 Deliverables

- Operational `INTERNAL_IT` scan zone for explicitly authorized internal IT scopes
- Internal host, IP, and CIDR scope validation
- CIDR scope validation for both individual IP targets and scoped CIDR targets
- Internal quick assessment profile using conservative Nmap service discovery only
- Scanner-job preparation uses the selected scope's scan zone instead of assuming external scans
- Scanner result import preserves internal in-scope assets as known assets
- Dashboard scope creation supports `EXTERNAL` and `INTERNAL_IT`
- Dashboard assessment profile selection is filtered by the selected scope zone

Epic 11 does not implement credential checks, brute force, exploit execution, lateral movement, internal OT reconnaissance, or distributed scanner nodes.

## Security Boundary

SignalHound is intended only for authorized security assessments. The current implementation performs no scanning, exploitation, credential attacks, brute force functionality, payload deployment, or destructive testing.
