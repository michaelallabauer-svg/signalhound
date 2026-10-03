# SignalHound Specification

SignalHound is an authorized external reconnaissance and exposure-management application.

The current implementation covers **Epic 1: Foundation**, **Epic 2: Scope Management and Scope Enforcement**, **Epic 3: Asset Inventory and Historization**, **Epic 4: Scanner Adapter Framework**, **Epic 5: External Discovery**, **Epic 6: Finding Normalization and Management**, **Epic 7: Change Detection**, **Epic 8: Basic Security Dashboard / UI**, **Epic 9: Scan Automation Foundation**, **Epic 10: Assessment Run Visibility**, **Epic 11: Internal IT Recon Foundation**, and **Epic 11.5: Production Hardening**.

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
- Placeholder registrations for `nmap`, `amass`, `nuclei`, and the internal `web_fingerprint` adapter
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

## Epic 11.6 Deliverables

- Assessment follow-up endpoint for preparing scoped web-fingerprinting jobs
- `web_fingerprint` adapter for conservative HTTP(S) metadata collection
- GUI action to prepare web-fingerprint jobs from completed assessment results
- Service-observation metadata for HTTP status, title, server header, redirect, and TLS certificate context
- Tests proving completed-assessment gating, scope filtering, duplicate skipping, and adapter normalization
- Explicitly deferred mobile OS-version verification to future manual asset context or MDM/provider integrations

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
- Completed assessments can prepare follow-up Nuclei scanner jobs for observed in-scope web services

## Epic 11 Deliverables

- Operational `INTERNAL_IT` scan zone for explicitly authorized internal IT scopes
- Internal host, IP, and CIDR scope validation
- CIDR scope validation for both individual IP targets and scoped CIDR targets
- Internal quick assessment profile using conservative Nmap service discovery only
- Internal CIDR import keeps hosts with open services or reliable discovery reasons, while ignoring Docker/NAT-only pseudo-up responses without open services
- Scanner-job preparation uses the selected scope's scan zone instead of assuming external scans
- Scanner result import preserves internal in-scope assets as known assets
- Dashboard scope creation supports `EXTERNAL` and `INTERNAL_IT`
- Dashboard assessment profile selection is filtered by the selected scope zone

Epic 11 does not implement credential checks, brute force, exploit execution, lateral movement, internal OT reconnaissance, or distributed scanner nodes.

## Epic 11.5 Deliverables

- Post-Epic-11 roadmap captured as `docs/roadmap-post-epic-11.md`
- Hardening review captured as `docs/hardening-epic-11-5.md`
- Production CORS validation rejects wildcard origins
- Configured request body size limit for API requests
- Scanner execution revalidates stored scanner commands against adapter-prepared commands before execution
- Scanner timeout and worker limit settings are bounded
- Celery worker concurrency, prefetch, acknowledgement, and task time limits are explicitly configured
- Docker Compose services use `no-new-privileges` and resource limits
- Tests cover hardening settings, request-size rejection, and scanner command tamper rejection

## Operational Maintenance

- Scopes are archived through soft deletion (`active=false`) so historical scan context remains auditable.
- Assessment runs can be archived after they are no longer queued or running.
- Archived assessment runs are hidden from default lists but can be shown explicitly.
- Archiving is audited.

## Security Boundary

SignalHound is intended only for authorized security assessments. Scanner execution is disabled by default and must remain scope-gated when enabled. The current implementation performs no exploitation, credential attacks, brute force functionality, payload deployment, or destructive testing.

## Epic 11.7 — Fingerprint visibility and end-user guidance

Delivered: latest-per-service fingerprint cards in asset details, explicit missing/error
states, source and observation timestamps, HTTP/TLS/redirect explanations, guided
assessment steps, contextual hover/focus/tap help, and keyboard row selection.
Existing service observations are reused without migrations. No product/OS confidence
is invented from headers. Automated UI coverage uses isolated API fixtures.

## Epic 12 — Vulnerability Intelligence and Enrichment

Delivered: provider adapters for NVD CVE/CVSS/CPE, FIRST EPSS and CISA KEV; conservative
observed-CPE/explicit-CVE linking; matching confidence separate from severity; immutable
intelligence snapshots and public-data cache; audited per-asset API; accessible guided
UI. No automatic confirmed findings, scope changes, scans or risk score. See
[delivery details](docs/epic-12-intelligence.md). Epic 13 is deferred.

## Epic 13 — Exposure and Risk Engine

Delivered: offline exposure-v1.0 heuristic with stored CVSS, EPSS, KEV, exposure, criticality,
finding-age and confidence components; explicit unknown-data ranges; current-lifecycle and
source-freshness handling; max aggregation; immutable audited risk snapshots and API;
accessible component explanations and snapshot history in asset details. No scanning or
automatic confirmation. Permanent context/ownership remains Epic 14. See
[algorithm and delivery](docs/epic-13-risk.md).

## Epic 14 — Asset Criticality, Context and Ownership

Delivered: persistent asset business criticality/environment/owners/team/location/notes;
organization-configured sites with reversible archive; revision-guarded updates, immutable
context history and site audit; accessible Inventory editor with help. Scanner observation
storage remains separate. New risk snapshots can inherit saved criticality with context
revision and source provenance; explicit overrides and old snapshots remain intact.
No segmentation, distributed scanning or identity/RBAC work is included. See
[delivery and API details](docs/epic-14-asset-context.md).

## Epic 15 — Network Segmentation Assessment

Delivered: immutable source/zone/IP/port ALLOW/DENY rules and separately persisted TCP check
snapshots. Deployment-authorized bind IPs, exact active Internal IT target scopes, limited
ports, dual execution gates, bounded probes/cooldown, audit and archive. A dedicated guided
UI explains outcomes and source limitations. No denial PASS is inferred from refusal or
silence; whole-zone isolation is not claimed. Distributed nodes remain Epic 16. See
[delivery, setup and outcome semantics](docs/epic-15-segmentation.md).
