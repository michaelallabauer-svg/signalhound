# Epic 12 — Vulnerability Intelligence and Enrichment

## Delivered boundary

Passive, explicit per-asset lookups with adapters for NVD (CVE/CVSS/CPE applicability),
FIRST EPSS and CISA KEV. No scanner execution, automatic findings, risk score, scheduled
sync, exploitation or asset-ownership model. Epic 13 and later remain unimplemented.

Four concepts remain separate:

1. **Observed software**: latest software-bearing service observation (including source,
   version, CPE and timestamp). Later web fingerprints do not erase software evidence.
2. **Potential vulnerability**: NVD CPE results marked `MAY_BE_AFFECTED`, moderate matching
   confidence, never confirmed merely because a version matches.
3. **Existing finding reference**: an explicit CVE on a scanner/manual finding, with the
   finding ID, source and lifecycle status captured at lookup. High identifier-linkage
   confidence does not assert exploitability or override resolved/false-positive status.
4. **External intelligence**: provider facts, including rejected CVEs, severity and exploit
   indicators. CVSS is separate from matching confidence; neither is organizational risk.

## User workflow

Inventory → select asset → **Vulnerability intelligence** → choose observed CPE or
finding CVE → **Look up intelligence**. The Findings tab points users to this view.
Inline help works with hover, keyboard focus/Escape and mobile click/tap. It explains
CVSS, EPSS, KEV, matching confidence and the public-query boundary.

Existing observations lacking CPE cannot be reliably converted from product names or
server headers. A new **authorized** Nmap discovery may provide CPE evidence; absence
of CPE or exact version is explicitly shown. This epic does not run discovery itself.
Nuclei imports now retain classification CVE identifiers. Existing CVE template IDs
remain usable without rescanning. Product/OS identities are never guessed from HTTP.

Snapshots show provider errors, unknown scores, rejected records, observation timestamps,
fetch/cache timestamps and truncated matches. An empty result never means “safe”.
KEV unknown differs from not-listed, which is used only after a complete catalog fetch.
EPSS missing differs from probability zero. CVSS carries its version, vector and scorer.

## API

- `GET /api/v1/assets/{id}/intelligence?organization_id=N&limit=20&offset=0`
  returns configuration, observed software, allowable evidence keys and newest snapshots.
  `limit` is bounded to 1–100; offset supports full history traversal.
- `POST /api/v1/assets/{id}/intelligence`
  body: `{"organization_id": N, "evidence_key": "<key returned by GET>"}`.
  Returns HTTP 201 with an immutable snapshot, status `COMPLETED`, `PARTIAL` or `ERROR`.
  The status is essential: 201 means the lookup attempt was recorded, not that providers
  succeeded. Invalid/foreign/stale evidence: 422; disabled: 409; asset/org mismatch: 404.
- OpenAPI documents request/read schemas. Provider-normalized payloads live in versioned
  source code and snapshot JSON; provider wire formats do not appear in the UI.

## Storage, migration and audit

Migration `20261003_0010` (parent `20260927_0009`) adds `intelligence_runs` and
`intelligence_cache`, without changing existing tables or findings. Run snapshots retain
source evidence, applicability configurations, timestamps, scores and provider outcomes.
Each lookup writes `intelligence.enriched` with run ID/reference/count/status.
The replaceable provider cache is separate from immutable snapshots and is reusable across
assets; it contains only public CVE/CPE intelligence, not inventory identifiers.

## Operation and security

Set `INTELLIGENCE_ENABLED=true` in local `.env`, then recreate backend (and worker for
consistent configuration). Defaults remain **false** in new deployments. No provider
credentials required. Scanner execution remains separately gated and scope validated.

Only existing evidence is accepted, not arbitrary provider URLs or query strings.
NVD receives CVE/CPE identifiers; FIRST receives up to 20 CVEs; CISA's catalog is downloaded
without identifiers. Hostnames, IPs, organization names and scanner evidence are not sent.
HTTPS uses certificate validation; redirects are refused. Requests have a 10-second socket
timeout and an 8 MB response cap. Network requests serialize per process and return a
retryable error when busy; uncached NVD requests are spaced by a fail-fast six-second
cooldown. Provider data is cached for 24 hours; failed calls are not cached, and expired
cache data is not silently returned as current.

The endpoint checks organization ownership but this is **not authentication/RBAC**:
existing deployment access controls still apply. No scope changes or active scan paths
are introduced. Passive public enrichment can read discovered/unverified inventory;
that does not authorize scanning those assets.

## Deliberate limitations / technical debt

- First 20 NVD matches per selected evidence item; larger lists are explicitly PARTIAL.
  Review full NVD applicability rather than treating this bounded list as exhaustive.
- CPE matching accepts only concrete vendor/product/version and simple URI/formatted
  bindings. Wildcards in identity/version, escaped/packed CPE bindings and fuzzy header
  matching are intentionally rejected rather than guessed.
- Configuration/environment conditions, distro backports and installed patch state are
  not evaluated. Even an exact CPE result is unconfirmed.
- Synchronous bounded single-evidence requests suit the current single-process deployment.
  Multi-instance global rate limiting, provider-specific API keys, asynchronous bulk sync,
  full pagination, cache retention and provider payload schema evolution are future work.
- Upstream availability/rate limits can yield partial or error snapshots; these do not
  overwrite prior successful evidence. There is no forced cache bypass.

## Files / acceptance

Created: intelligence API, provider/orchestration package, snapshot/cache models,
Alembic migration, intelligence React component, backend/API tests, browser tests,
and this delivery document.
Modified: app/router/model registration, settings, Nmap/Nuclei evidence normalization,
Compose/environment defaults, inventory/findings UI, API types, styles, existing scanner
and UI fixtures, README, SPEC and roadmap.

Acceptance checks: provider normalization; history/cache expiry/audit; no new findings or
jobs; organization/evidence validation; disabled behavior; partial/empty/error separation;
CPE conversion and ambiguity rejection; no stale software fallback; safe metadata and
HTML rendering; bounded transport/redirect refusal; keyboard and narrow-screen help;
full backend/browser suites; local/frontend and Docker builds; migration to head; live
API/UI smoke and public-provider smoke. Verified on 2026-10-03: **74 backend tests passed locally and in the fresh Docker image**
(one existing Starlette/httpx deprecation warning); **7 Playwright browser tests passed**;
frontend and Docker builds succeeded. Compose PostgreSQL is on `20261003_0010 (head)`.
Live API GET, invalid-evidence rejection, OpenAPI, UI rendering and keyboard tooltip smoke
passed without JavaScript errors. A transactional PostgreSQL/API smoke fetched real
NVD/EPSS/KEV data, persisted/read a snapshot and rolled back all smoke inventory/results.
All five Compose services are running. No scanner jobs were started.

Migration commands use the Compose backend/PostgreSQL network, not an unrelated host
PostgreSQL instance. Local deployment lookups are enabled; repository defaults remain off.

Next recommended epic: **13 — explainable Exposure and Risk Engine**, only on request.
