# Epic 16 — Distributed Scanner Nodes

## Delivered

Outbound/pull execution of the existing bounded TCP segmentation assessment from multiple
explicitly authorized network locations. Nodes have individual random credentials, pinned
source IP and network/port grants, heartbeat and version reporting, capability restrictions,
revocation/rotation, finite job leases and independently stored results.

The first supported capability is **tcp_connect_v1**. No remote shell, arbitrary command,
Nmap/Nuclei dispatch, full-port scanning or background assessment expansion is introduced.
Those adapters can later use this authorization framework through dedicated bounded protocols;
they are not silently enabled. Epic 17 assessment aggregation and Epic 22 human SSO/RBAC remain
separate. The old backend-local segmentation path remains compatible and cannot execute a
rule assigned to a remote node.

## Trust and transport

- Each node gets a cryptographically random 256-bit bearer credential. Only its SHA-256 digest
  is persisted server-side; raw credentials are written once to a new owner-only (0600) file.
  No public enrollment/rotation/revocation endpoint, browser token, command-line token argument
  or token log. Deployment administrators use the local CLI with database access.
- HTTPS is mandatory for node endpoints and the standalone client validates certificates and
  hostnames. Private CA bundles are supported; disabling certificate validation is not.
  HTTP redirects and ambient proxies are not used by the client. The optional insecure override
  is **loopback-only**, server and client separately, and defaults off.
- With TLS termination, configure Uvicorn's trusted forwarded-proxy IPs to the actual proxy
  addresses only. Never trust arbitrary forwarded headers. Protect the backend connection to
  the TLS proxy; do not expose that plaintext leg to remote nodes. The default local Compose
  deployment does not manufacture or install a production TLS certificate.
- The credential authenticates a registered node, not its physical location or honesty. Network
  measurements are explicitly marked **authenticated_node_report**, not independently attested.
  Source IP is pre-NAT and belongs to the node's namespace. Administrators must verify routing
  and the intended location; an Inventory Site name is not an authorization.
- Human-facing read/queue APIs retain existing organization consistency checks and deployment
  access controls. They do not claim to provide user authentication before Epic 22. Node-facing
  protocol endpoints require the node credential and TLS on every request.

## Administrator setup

1. Create approved **Internal IT IP/CIDR scopes**. A node may have up to 32 selected scope IDs
   and 16 TCP ports; at most 16 active nodes per organization. Registration pins the network
   values as well as IDs, so widening a scope cannot silently broaden an existing grant.
2. Configure a trusted HTTPS endpoint for SignalHound. Preserve existing local UI/API ports.
3. On the deployment host, register a node using the backend environment. Example with
   placeholders (replace organization/scope IDs, addresses and hostname with reviewed values):

   ```bash
   cd backend
   .venv/bin/python -m app.node_admin register \
     --organization 1 --name 'Authorized branch scanner' --bind-ip 192.0.2.2 \
     --scope 7 --port 443 --port 5432 \
     --url https://signalhound.example \
     --credentials /private/node-credentials.json
   ```

   With Compose, use the container's database environment and a private bind-mounted export
   directory, e.g. `docker compose run --rm --no-deps -v /private/export:/credentials backend
   python -m app.node_admin register ... --credentials /credentials/node-credentials.json`.
   The output contains only node ID/file path, never the credential. Securely transfer the file
   to its node owner, preserving 0600 permissions; do not paste it into chat or source control.
   The destination file must not already exist. If the database commit fails after export,
   discard that uncommitted credential file and rerun to a new file.
4. Build the standalone client from repository root:

   ```bash
   python3 scripts/build_node.py /private/signalhound-node.pyz
   ```

   Copy the `.pyz` and private credential file to the approved node. The client needs only
   **Python 3.12+**, no backend, Docker, scanner binaries or third-party Python packages. Native
   macOS/Linux execution uses that host's network namespace. Running it in Docker instead
   retains the container/NAT limitations. The configured bind IP must really exist there.
5. First verify heartbeat without target traffic:

   ```bash
   python3 /private/signalhound-node.pyz \
     --config /private/node-credentials.json --spool /private/pending-result.json --once
   ```

   Add `--ca-bundle /private/trusted-ca.pem` for a private CA. The spool path must be separate
   from credentials, in a private directory, and must not belong to another running client.
   Run only one client instance per node identity.
6. Enable all server gates in the authorized deployment:
   `SCANNER_EXECUTION_ENABLED=true`, `SEGMENTATION_EXECUTION_ENABLED=true`,
   `NODE_EXECUTION_ENABLED=true`; recreate the backend/worker services after changes.
   Start the node with **--execute** (without --once for 15-second outbound polling).
   Heartbeat-only mode is the default; registration alone does not start checks.
7. In **Scanner nodes**, refresh and verify source, grants, version and heartbeat. In
   **Segmentation**, choose `Node: …`, prepare an ALLOW/DENY rule, then explicitly queue it.
   Refresh to see job progress and the separately recorded result. Queueing is not a PASS.

Credentials and grants are not editable through the UI. To change an authorized location or
network grant, revoke the old node and register a reviewed replacement. To rotate a credential
without changing grants:

```bash
python -m app.node_admin rotate --node 3 --url https://signalhound.example \
  --credentials /private/new-node-credentials.json
python -m app.node_admin revoke --node 3
```

Rotation increments credential generation, invalidates old tokens and outstanding jobs, and
requires a new heartbeat. Revoked identities cannot be restored. Historical results remain.
The registered-node `node-` source ID prefix is reserved; static backend source configurations
must use a different prefix.

## Protocol and execution semantics

1. **Prepare**: reuse immutable `SegmentationRule` and its exact source/zone/IP/port snapshot.
   Remote rules carry node identity and pinned network grants in the source snapshot.
2. **Queue**: manual `POST /nodes/rules/{id}/queue`. All server gates and scope authorization
   required. At most one outstanding job per rule, max 100 per node. Offline nodes may queue,
   but the queue entry expires after ten minutes rather than running much later unexpectedly.
3. **Heartbeat**: authenticated POST `/nodes/self/heartbeat` supplies version, capabilities and
   client execution flag. Online means seen within 90 seconds. Ready also requires supported
   **1.0.0** version and `tcp_connect_v1`; arbitrary capabilities never grant permissions.
4. **Pull**: POST `/nodes/self/pull` leases one job for 60 seconds, only to its owning ready node.
   It returns a random lease secret, not executable target instructions. One active lease/run
   per node. No browser/admin list exposes lease hashes or secrets.
5. **Start**: POST `/nodes/self/jobs/{id}/start` with lease secret, separately authenticated.
   Node, scope activity/ownership/type, pinned network, immutable rule, capability and gates
   are rechecked. Organization/node/job locks serialize mutations on PostgreSQL; the shared
   five-second start cooldown also applies to backend checks. A start is accepted once.
   The client must receive/validate the start response within three seconds and then performs
   exactly one two-second TCP connection bound to its fixed local IP. It independently enforces
   local pinned networks and ports; no default-interface fallback, DNS or payloads.
6. **Result**: POST `/nodes/self/jobs/{id}/result` with the same lease secret and typed observation.
   The result deadline is 15 seconds after start. The server checks source/endpoint, observation
   consistency and state and computes the verdict itself using Epic 15 semantics. No node
   supplied risk score or PASS is trusted. A new immutable `SegmentationCheck` stores expected
   state, node ID, job ID, authenticated report provenance, version and receive time.
7. **Idempotence**: an identical duplicate result returns the existing check; a conflicting
   duplicate is rejected. A lost start response never triggers a second execution attempt.
   A measured result is spooled privately before upload, and only that exact upload may be
   retried. Expired/revoked results are rejected; their local pending file is retained for
   operator inspection, not silently discarded or used to reexecute a probe.

Jobs: QUEUED → LEASED → RUNNING → COMPLETED, or CANCELLED/EXPIRED. COMPLETED does not mean PASS;
see the linked check verdict. Expiration can mean execution happened but a result was lost.
No automatic lease requeue, reassignment, probe retry or false clean finding. Clock labels are
server timestamps; the client's start budget uses elapsed monotonic time.

Revocation stops future authorizations and rejects further reports, but cannot undo an already
started connection. Scope/rule changes after a valid start do not erase a legitimate historical
result. A crashed client/server can lose evidence; the system does not claim exactly-once
physical network activity. On transport, policy or acknowledgment errors the client stops with
a non-secret diagnostic; run a supervised service only with an operator-reviewed restart policy.
For a rejected/expired spool, inspect it privately and archive it before using a fresh spool path;
never treat its evidence as server-accepted or automatically requeue the old job.

## Persistence, API and UI

Migration **20261004_0014** adds `scanner_nodes` and `node_jobs`; existing rules/checks and local
source snapshots remain compatible. Node registration/rotation/revocation and each job lifecycle
transition are audited without secrets. Registration/rotation CLI transactions hold organization
locks. Credentials and lease tokens are stored only as hashes server-side.

Read APIs: `GET /nodes?organization_id=N&limit=50&offset=0`,
`GET /nodes/jobs?organization_id=N&rule_id=R&limit=20&offset=0` (rule filter optional, max100/page).
Node endpoint base is `/api/v1/nodes`. Self endpoints derive node/organization from the bearer
credential, never from an untrusted organization or node ID in the request body.

**Scanner nodes** shows online/offline/revoked, readiness, version, heartbeat, approved ports,
capability and job state with hover/focus/tap help. **Segmentation** selects a registered node,
queues explicitly, displays node job status separately and shows completed evidence in the
existing history. Refresh is explicit; no hidden automatic execution from visiting either tab.

## Verification scope

Tests cover authentication/TLS enforcement, missing gates, node readiness, cross-node/org/lease
isolation, source and network grant revalidation, revocation/rotation, lease expiry without
re-execution, typed result validation, duplicate idempotence, cooldown and private credential
export. Client tests cover private-file permissions, independent endpoint grants, lost start and
lost result behavior. A real HTTPS Uvicorn-to-stdlib-client integration uses an isolated loopback
TCP listener: untrusted certificate rejection, heartbeat-only mode, authorized pull/start/probe,
zero payload bytes and persisted PASS are verified. No LAN or external target scanning is needed.

### Delivery verification (2026-10-04)

- **209 backend tests** passed locally and in the fresh container, including real HTTPS and
  controlled loopback TCP. Existing Starlette/httpx deprecation warning only.
- **16 browser tests** passed: node setup/readiness/help, remote-only dispatch, separate queue
  state versus result, existing workflows and narrow-screen layout.
- Frontend production build, backend/worker/frontend images and standalone zipapp build/CLI
  smoke passed. The client reserves owner-only evidence storage before the TCP probe. A
  `START_AUTHORIZED_NO_RESULT` marker after interruption is retained for review, not replayed.
- PostgreSQL upgraded to **20261004_0014 (head)**; `alembic check` reports no new operations.
- Transactional PostgreSQL API smoke covered registration, queue, heartbeat, lease/start,
  actual loopback TCP/no payload, immutable result, duplicate acknowledgment, rotation and
  revocation. All fixture organizations/scopes/nodes/jobs/checks/audit rows were rolled back.
- All five services running. Live API/UI verified on 8010/8011; plaintext node protocol
  requests rejected, real disabled/empty state and mobile layout correct, no JavaScript errors.
- Current deployment has **no registered operational nodes**; `NODE_EXECUTION_ENABLED=false`.
  No LAN probes or target scanner jobs were started. Operational use still requires reviewed
  node grants, private credential provisioning and a trusted HTTPS endpoint, as documented above.
