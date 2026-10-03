# Epic 13 — Explainable Exposure and Risk Engine

## Scope and decisions

Offline, on-demand prioritization from current findings and persisted Epic 12 intelligence.
It never launches scans, fetches providers, creates confirmed findings or changes scopes,
asset state, finding status or severity. It is a **heuristic priority**, not a calibrated
probability of compromise, financial risk model, or proof of vulnerability.

Inventory → asset details → **Exposure and risk** → optionally supply exposure/criticality
and rationale → **Calculate priority**. Each click records an immutable, audited snapshot.
Unknown is the default. The user can inspect every contribution and its source with
hover/focus/tap help. History is paginated. Recalculate after data/lifecycle changes;
old snapshots deliberately retain their historical inputs and algorithm version.

Exposition and criticality are **per-calculation analyst assumptions**, not inferred from
scope zones or public addresses and not permanent asset attributes. Non-unknown context
requires a rationale of at least 10 characters. Permanent business ownership, environment,
site and asset criticality management remain Epic 14. No new authentication/RBAC is added.

## Versioned algorithm: `exposure-v1.0`

Each issue has a persisted ledger of raw inputs, normalized values, known/unknown state,
weights, sources and lower/upper contributions:

| Component | Calculation | Maximum |
|---|---|---:|
| CVSS | base score / 10 | 30 |
| EPSS | probability (0–1) | 20 |
| CISA KEV | listed = 1; not listed in fresh complete catalog = 0 | 20 |
| Exposure | Internet = 1; internal reachability = 0.4 | 15 |
| Asset criticality | Low = .25; Medium = .5; High = .75; Critical = 1 | 10 |
| Finding age | min(days since first seen / 90, 1) | 5 |

Multiply the additive subtotal by **identifier-linkage confidence**: High = 1,
Moderate = .75, Low = .5. Unknown confidence spans [.5, 1]. This does **not** mean that
exploitation is confirmed; the unadjusted subtotal remains visible. CPE-only potentials
normally have moderate confidence and no finding age. Severity labels are preserved for
traceability but never silently converted into CVSS numbers.

These fixed weights are an explicit initial policy choice, not externally validated
risk calibration. Algorithm changes require a new version. Values, the full weight set,
confidence factors, component contributions and calculation time are persisted so the
numerical ledger can be replayed independently of mutable findings or provider data.

An unknown additive component spans [0, its maximum], **not a known zero**. The final range
is [sum(lower) × confidence_lower, sum(upper) × confidence_upper], rounded to two decimals.
A scalar issue `score` exists only when all seven components are known. These are heuristic
bounds, not statistical confidence intervals. Invalid/nonfinite/out-of-domain numbers
are unknown. Zero EPSS and known KEV=false are valid known values.

Bands: LOW <30, MEDIUM 30–<60, HIGH 60–<80, CRITICAL ≥80. A range crossing bands is
UNCERTAIN. These are priority labels, not replacements for finding severity.

**Asset aggregation is maximum, never sum**: independently take max(lower) and max(upper)
across eligible entries. Multiple issues/CPE references cannot inflate a total by addition.
Entries sort by upper bound descending, then lower bound, then stable identity key. This
is a review queue: broad uncertainty may sort high and must not be mistaken for confirmed
high risk. Organization-wide posture/scoring dashboards remain later roadmap work.

## Eligibility, lifecycle and freshness

- Current open findings are included even without intelligence (showing missing components).
  RESOLVED and FALSE_POSITIVE findings are explicitly excluded; ACCEPTED_RISK remains
  visible, since acceptance does not remove technical exposure. Reopening restores eligibility.
- Each CVE on a finding is a distinct entry; unlinked findings retain an unenriched entry.
- CPE-only candidates remain `MAY_BE_AFFECTED`; no confirmed Finding is generated. Separate
  CPE evidence is not automatically suppressed by a resolved finding on the same CVE:
  that might represent a different service/configuration. Max aggregation avoids summation.
- Only the newest intelligence attempt for each **current evidence key** is considered,
  including failures. A failed new attempt never silently revives a previous success.
  Changed/inactive software observations make older CPE evidence ineligible.
- NVD fetch age must be ≤30 days; EPSS/KEV fetch age ≤2 days. EPSS additionally requires
  its own model date ≤3 days. Missing, failed, future-dated or stale provider data is unknown.
  Repeatedly reusing a cached response cannot reset its source freshness.
- Rejected CVEs are not potential vulnerability matches. A separate existing finding is
  not erased by external rejection; it remains an unenriched item for review.
- Missing/future/older-than-30-day observation timestamps are warned about. Truncated or
  partial intelligence is explicitly surfaced and prevents COMPLETE aggregate status.
- Finding age is elapsed time since first_seen, not an SLA or lifetime since reopening.
  Future dates are unknown. An inactive asset is marked in snapshot context but is not
  assumed remediated or safe.
- No eligible entries produces NO_EVIDENCE with null bounds, **never zero risk**.

## API, models and migration

- `GET /api/v1/assets/{id}/risk?organization_id=N&limit=10&offset=0`: algorithm version and
  immutable snapshot history, newest first. Limit 1–50, nonnegative offset.
- `POST /api/v1/assets/{id}/risk`: body includes `organization_id`; optional
  `exposure` (UNKNOWN/INTERNAL/INTERNET), `criticality` (UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL),
  `rationale` (max 2000 characters). Returns 201 with result and component ledger.
- Supplied weights, scores, source values and unknown extra fields are rejected (422).
  Foreign/missing asset returns 404; this ownership consistency check is not authentication.
- At most 500 findings, 5000 intelligence-history rows, and 1000 resulting entries per
  interactive asset calculation. Excess returns 422 without saving a misleading partial score.
- Migration **20261003_0011**, parent 20261003_0010, adds `risk_snapshots` with indexed
  asset linkage, creation time, algorithm version, snapshot context and JSON result ledger.
- Audit event `risk.calculated` stores asset, snapshot ID, version and result completeness.
  Existing tables, scanner execution gates, and scope enforcement are unchanged.

Apply using Compose (not an unrelated PostgreSQL on the host):

```sh
docker compose build backend worker frontend
docker compose run --rm --no-deps backend alembic upgrade head
docker compose up -d --no-build backend worker frontend
```

## Files / acceptance / limitations

Created: risk engine/service package, risk API/model/migration, Risk React component,
backend and browser tests, this document. Modified: router/model registration, inventory
view, frontend API/types/styles, existing browser fixtures, README, SPEC and roadmap.

Acceptance covers exact replay, weights/bounds/monotonicity, unknown-vs-zero semantics,
confidence separation, lifecycle changes/history preservation, current evidence selection,
failed/stale/truncated/rejected intelligence, org/input isolation, no scanner/finding
mutation, explicit resource limits, narrow-screen/keyboard interaction, HTML-safe text,
and local/container/build/migration/API/UI verification.

Known limitations: fixed uncalibrated heuristic policy; context applies asset-wide within
one snapshot rather than per service; no automatic recalculation or bulk organization
ranking; no permanent asset business context; no historical re-evaluation of old database
state. First_seen age does not reset on reopening. Retention/large-scale history querying,
per-service reachability evidence, sensitivity calibration and policy configuration are
future work. Existing Starlette/httpx test deprecation warning is unrelated.

Recommended next step only on request: **Epic 14 — Asset Criticality, Context and Ownership**.

## Verification receipt — 2026-10-03

- 92 backend tests passed locally and in the fresh Docker image; 9 Playwright tests passed.
- Local/frontend and backend/worker/frontend Docker builds succeeded.
- Compose PostgreSQL migration is `20261003_0011 (head)`; all five services run.
- Live API POST/GET created/read snapshot #1 from existing inventory, using UNKNOWN context
  rather than invented assumptions. Its INCOMPLETE range correctly reflects missing data.
- Finding payloads and scanner-job counts were unchanged; cross-organization read rejected.
- Live GUI displayed the saved snapshot, expanded contribution ledger and keyboard tooltip
  without JavaScript errors. No scans or public intelligence requests were started.
- An inherited disabled-intelligence test depended on the deployment environment; it now
  explicitly sets its tested flag and passes with local intelligence enabled as well.
- No known failing checks; the pre-existing Starlette/httpx deprecation warning remains.
