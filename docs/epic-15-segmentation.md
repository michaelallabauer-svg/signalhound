# Epic 15 — Network Segmentation Assessment

## Delivered boundary

One manually triggered TCP endpoint check from a deployment-authorized **backend network
namespace**, compared with a persistent, immutable ALLOW/DENY rule. A rule records a source,
an explicitly selected target zone, a literal IP, one approved TCP port and policy rationale.
Preparing a rule sends no network traffic. Results are independent, timestamped snapshots
of both expected policy and observed connectivity. Archive retains all history.

This is a conservative segmentation assessment foundation, not a port scanner, firewall
policy verifier or distributed scanner. No DNS, shell commands, CIDR expansion, UDP,
application payloads, scheduled jobs, retries or automatic vulnerability findings. No
inventory, business-context, intelligence or risk snapshot is modified. Epic 16 nodes
and later assessment aggregation are deliberately not implemented.

## Results: no false assurance

| Expected | Observed | Status | Outcome |
|---|---|---|---|
| ALLOW | TCP accepted | PASS | PASS |
| DENY | TCP accepted | FAIL | UNEXPECTED_ACCESS |
| ALLOW | TCP refused | FAIL | UNEXPECTED_BLOCK |
| DENY | TCP refused | ERROR | ERROR (denial unverified) |
| Either | Timeout / routing error / bind failure | ERROR | ERROR |
| Either | Disabled / archived / authorization missing or changed | NOT_TESTED | NOT_TESTED |

`UNEXPECTED_BLOCK` means the required TCP connection was refused, **not** a proven firewall
block. A closed service can refuse connections on a completely open network. A two-second
timeout could mean packet loss, routing problems, an unavailable host or filtering.
Consequently this version **does not issue PASS for a DENY rule**. Proving enforced denial
requires additional independently trustworthy network/policy evidence beyond this Epic.
PASS for ALLOW confirms only the exact endpoint and time, never an entire zone.

Evidence records bind IP (and ephemeral source port), destination, attempted flag,
transport, duration, raw observation category and explanation. `created_at` is check start
time. Actual source means the socket's **pre-NAT** bound address; it is not an attestation of
what the remote host sees. Docker Desktop is not automatically a Mac/LAN vantage point.

## Authorization and setup

Default deployment has no sources and segmentation execution disabled. Nothing is enabled
automatically by the migration or application startup. Inventory Sites are labels, **not**
scanner authorizations. The deployment administrator must select a real source IP and verify
its network namespace/routing/NAT before making claims about an intended source zone.

1. In Scopes create an approved **Internal IT** IP/CIDR target scope in the organization.
2. Configure backend `SEGMENTATION_SOURCES_JSON`, using the real organization/scope IDs and
   an IP assigned to a backend network interface. Example shape only (do not copy placeholder
   addresses/IDs as operational configuration):

   ```json
   [{"id":"backend-lab","organization_id":1,"name":"Authorized lab backend",
     "bind_ip":"192.0.2.2","target_scope_ids":[7],"allowed_ports":[443,5432]}]
   ```

   In a Compose `.env`, put the JSON on one line, optionally single-quoted. Direct backend
   execution can use its own environment or `.env`. Compose passes both settings explicitly.
3. Enable **both** `SCANNER_EXECUTION_ENABLED=true` and
   `SEGMENTATION_EXECUTION_ENABLED=true` only for that authorized environment. Restart/recreate
   the backend after changing deployment configuration. No node is registered by this action.
4. Open **Segmentation**, refresh configuration, prepare a rule, review source/target/expectation,
   then **Check one TCP endpoint**. Do not equate this with checking every host in a network.

Sources are deployment-owned (not user-editable API records): max 16, unique IDs, one literal
non-wildcard unicast IPv4/IPv6 address each, up to 32 explicit target-scope IDs and 16 distinct
ports. A source is organization-specific. Only an active selected scope in the same organization
can authorize a target; a different overlapping scope never substitutes for it. IPv6 zone IDs,
link-local/multicast/unspecified/IPv4-mapped addresses, and IPv4 network/broadcast targets
in CIDRs are rejected. Source/destination address families must match.

Source binding is mandatory with **no fallback**. Source and zone configuration snapshots
must still match immediately before execution, including labels; after any change, review
and prepare a new rule. Revoked/changed authorization yields persisted NOT_TESTED, not traffic.
Scopes are locked while checking. PostgreSQL organization/rule row locks serialize checks and
archival across processes; a shared five-second cooldown across the organization's rules limits
starts. Max 100 active rules per organization. One synchronous socket, two-second timeout,
no arbitrary scanner flags. Execution does not use Celery or the Nmap profile.

Organization IDs provide ownership consistency, not caller authentication. Existing deployment
access controls still apply; authenticated roles/node identity remain later epics. An already
started TCP check cannot be recalled; rule archival and scope changes serialize behind it.
A process crash can roll back result storage after an attempted connection; execution is not
claimed to be exactly-once. No blind auto-retry is implemented.

## API and persistence

All routes under `/api/v1/segmentation`:

- `GET /config?organization_id=N`: authorized source list, gates, configuration error and limits.
- `GET /rules?organization_id=N&limit=50&offset=0`: immutable rules incl archived, newest first;
  max page size 100.
- `POST /rules`: organization_id, name, source_id, scope_id, target, port, expected, rationale.
  Rationale >=10 characters. Preparation only; invalid boundaries return 422.
- `POST /rules/{id}/archive`: organization_id. Idempotent; no delete or policy mutation.
- `POST /rules/{id}/checks`: organization_id. Saves one result, including NOT_TESTED if blocked.
  Cooldown returns 429 with Retry-After; foreign rules return 404.
- `GET /rules/{id}/checks?organization_id=N&limit=20&offset=0`: independent check history;
  max page size 100. No update/delete endpoint.

Migration **20261004_0013** adds `segmentation_rules` and `segmentation_checks` with FKs,
indexes and port/expected/status/outcome constraints. Existing tables/rows unchanged.
`segmentation.prepared`, `.archived`, `.checked` audit events record the owning organization
and result. Historical expectations use `segmentation-tcp-v1`; later rule/config changes do
not reinterpret previous results.

## User experience and verification

Dedicated Segmentation tab: three-step explanation; approved source/zone/port selectors;
immutable expected policy beside observed results; history paging; disabled/empty/error states;
archive; keyboard/hover/tap help and narrow-screen layout. Source setup is shown only where
it blocks use, with a separate administrator details section.

Automated coverage includes all verdict paths, both execution gates, preparation without traffic,
revoked/mutated source/scope authorization, organization isolation, exact overlapping scope
selection, rejected input/ranges/DNS, active rule cap, history/audit/archive, source bind failures,
configuration limits and cooldown. The real socket smoke uses a temporary **loopback-only**
listener and verifies that no application bytes are sent. Browser coverage verifies guided
preparation vs execution, immutable history, inconclusive results, archive, disabled deployment,
keyboard help, safe text rendering and mobile width. Live LAN isolation is not asserted.

### Delivery verification (2026-10-04)

- 155 backend tests passed locally and in the freshly built backend image (existing
  Starlette/httpx deprecation warning only); 14 browser tests passed.
- Frontend production build and backend/worker/frontend Docker builds passed.
- PostgreSQL upgraded to `20261004_0013 (head)`; `alembic check` reports no new operations.
- Transactional PostgreSQL API smoke exercised a real container-loopback listener, PASS,
  no application payload, snapshot readback, cooldown, archive and NOT_TESTED. All fixture
  organizations/scopes/rules/checks/audit rows were rolled back; deployment settings unchanged.
- API `8010`, UI `8011` and all five services running. Live browser smoke verified the real
  empty/disabled configuration, administrator explanation, mobile width and no JS errors.
- No LAN probes were run. No source is configured in the current deployment and segmentation
  execution remains disabled pending explicit source/target authorization configuration.
