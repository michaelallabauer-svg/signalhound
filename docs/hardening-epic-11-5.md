# Epic 11.5 Production Hardening Report

## Scope

Epic 11.5 reviews the existing SignalHound platform after Epic 11 and applies focused hardening without adding vulnerability enrichment, risk scoring, scanner nodes, RBAC, or later-roadmap functionality.

## Findings and Implemented Fixes

### API Security

Finding: API requests had no explicit request body size limit.

Implemented:

- Added `MAX_REQUEST_BODY_BYTES`.
- Added request body size middleware returning HTTP `413` when `Content-Length` exceeds the configured limit.
- Added tests for large request rejection.

Finding: Production CORS could be misconfigured to wildcard origins.

Implemented:

- Added settings validation that rejects `CORS_ORIGINS=*` when `ENVIRONMENT=production` or `prod`.
- Added tests for production wildcard rejection.

### Scanner Execution Integrity

Finding: Scanner execution used the persisted `prepared_config.command` from the database. API clients cannot directly submit arbitrary commands, but a persisted command should still be treated as untrusted at execution time.

Implemented:

- Scanner execution now asks the adapter to prepare the command again from the stored target, scope, and organization.
- The stored command must match the adapter-prepared command exactly.
- A mismatch fails before external tool execution.
- Added a scanner command tamper-rejection test.

### Scanner Timeout Bounds

Finding: Scanner timeout configuration had no validation bounds.

Implemented:

- Bounded `SCANNER_TIMEOUT_SECONDS` to 5-1800 seconds.
- Added a test for invalid timeout rejection.

### Worker Security

Finding: Celery worker execution had no explicit concurrency or task time limits in application configuration.

Implemented:

- Added `CELERY_WORKER_CONCURRENCY`.
- Added hard and soft task time limits.
- Set `worker_prefetch_multiplier=1`.
- Enabled late acknowledgement and worker-lost rejection.

### Container Runtime

Finding: Docker Compose services had no explicit resource or no-new-privileges settings.

Implemented:

- Added `security_opt: no-new-privileges:true`.
- Added `pids_limit` and `mem_limit` to Postgres, Redis, backend, worker, and frontend services.

Aggressive capability dropping and non-root scanner execution were deferred because Nmap host discovery may require capabilities that must be tested carefully.

### Secrets and Logging

Finding: No hard-coded production secrets were found in the reviewed source. Scanner raw output remains accessible through authenticated-by-environment local APIs, but there is no application authentication yet.

Implemented:

- No scanner raw output is intentionally logged by the application scanner execution path.

Deferred:

- Add authentication and RBAC in Epic 22 or an explicitly requested earlier security epic.
- Add raw-output access controls after authentication exists.
- Add structured secret redaction for future provider integrations.

## Deferred Improvements

- Authentication and RBAC.
- Enterprise SSO / Entra ID.
- Per-user authorization checks.
- API rate limiting.
- CSRF protections for browser-authenticated future sessions.
- Non-root scanner containers.
- Capability-minimized scanner containers.
- Dedicated scanner filesystem sandbox.
- Separate Docker networks for frontend/API/data/scanners.
- Database backup and restore automation.
- TLS enforcement for production database and Redis connections.
- Retention policies for scanner raw output and audit data.

## Scope Enforcement

Scope enforcement remains unchanged. Scanner job preparation and assessment creation still validate targets against active scopes before jobs are created. Scanner execution now adds an additional command-integrity check but does not broaden scope.

## Tests

New tests cover:

- Production wildcard CORS rejection.
- Invalid scanner timeout rejection.
- Request body size rejection.
- Scanner command tamper rejection.

## Acceptance Criteria

- Hardening findings documented: PASS
- Implemented fixes documented: PASS
- Deferred improvements documented: PASS
- Tests added: PASS
- Scope enforcement preserved: PASS
- Later Epics not implemented: PASS
