# Epic 14 — Asset Criticality, Context and Ownership

## Delivered scope

Persistent, analyst-maintained business context is separate from scanner observations:

- Criticality: LOW, MEDIUM, HIGH, CRITICAL, or **unclassified** (`null`). Existing assets
  are not silently assigned a business importance.
- Environment: PRODUCTION, TEST, DEVELOPMENT, INFRASTRUCTURE, UNKNOWN.
- Technical owner, organizational/business owner, responsible team (optional labels).
- Organization-configured location/site, plus optional context notes.

No hard-coded site names or production seed locations. No external directories, identity
accounts, owner notifications, ticket creation, scans, segmentation checks or RBAC are
introduced. These remain later epics. Ownership labels do not grant access or authorize
scanning. Context can also describe discovered/unverified assets without authorizing them.

## End-user workflow

Inventory → select asset → **Asset business context**. Fill known values and save.
Defaults are unknown/unassigned; blank owner/team/notes fields clear those values.
**Manage organization locations** creates, renames/describes, archives or restores sites.
Creating a site does not silently assign it: select it and save the asset context.

Inline hover/focus/tap help explains business vs technical severity, ownership, environments
and locations. Labels are explicitly associated with inputs, independently of help buttons.
The UI shows saved revision/time, unsaved edits, save results and change history. A conflicting
save retains the draft. **Reload saved context (discard edits)** is explicit and intentional;
the client never silently advances a draft's revision because locations were refreshed.

Sites are shared within an organization. Archiving is reversible and leaves existing
assignments visible. New assignments to archived sites are rejected. Existing assigned
archived sites may be preserved while other context fields change. Names are unique per
organization, including archived sites, after whitespace normalization and Unicode casefold.
Sites have their own revision guard; name reuse in another organization is allowed.

## Storage, history and concurrency

Migration `20261003_0012` (parent `20261003_0011`) adds three tables:

- `sites`: organization ownership, configurable name/description, active flag, revision,
  timestamps and normalized per-organization unique name.
- `asset_business_contexts`: one-to-one asset context, nullable criticality, explicit
  environment, owner/team/site/notes fields, revision and last update time.
- `asset_context_history`: immutable before/after JSON snapshots with asset, unique
  revision and timestamp. Site labels at context-change time are included.

GET of an unconfigured asset returns defaults with revision 0 without creating rows.
PATCH applies only supplied fields. Null clears nullable fields; environment resets via
UNKNOWN (not null). True no-ops create neither a revision nor an audit/history record.
Every real change writes history and `asset.context.changed`; site creation/changes write
`site.created`/`site.changed`, including before/after site data for auditing.

The asset row is locked during context writes, including first creation. Expected revision
comparison prevents lost updates. Referenced sites are locked/reloaded for assignment
validation, preventing an archive race. Site updates lock and compare their own revision.
Invalid and foreign-organization assignments are rejected before changes are committed.
Site renames update current labels but do not rewrite historical context or risk snapshots.
No hard-delete route is provided; no existing asset/scanner/finding table is modified.

## API

All routes are under `/api/v1`; organization consistency is enforced. This is **not**
authentication/RBAC: existing deployment access controls still apply.

| Method / path | Purpose |
|---|---|
| GET `/assets/{id}/context?organization_id=N` | Current context or explicit unset defaults |
| PATCH `/assets/{id}/context` | Partial update with `organization_id`, `expected_revision` and ≥1 context field |
| GET `/assets/{id}/context/history?organization_id=N&limit=20&offset=0` | Newest-first immutable changes; limit 1–100 |
| GET `/sites?organization_id=N&active=true` | Configured sites; omit active to include archived sites |
| POST `/sites` | Create with organization, name and optional description |
| PATCH `/sites/{id}` | Rename/describe/archive/restore with organization and expected revision |

Responses: context/site changes 200, created site 201, missing/foreign object 404,
revision/name conflict 409, invalid fields/archived new assignments 422. Unknown request
fields are rejected. Names/owners/team max 160 characters; notes/descriptions max 2000.
Timezone-aware timestamps are returned consistently in local SQLite tests and PostgreSQL.

Example context PATCH body:

```json
{
  "organization_id": 1,
  "expected_revision": 0,
  "criticality": "HIGH",
  "environment": "PRODUCTION",
  "responsible_team": "Platform operations"
}
```

## Epic 13 integration / compatibility

New risk calculations **default to saved asset criticality**. Omitting `criticality` or
sending null to the risk POST selects inheritance. Explicit `UNKNOWN` still means an
unknown snapshot override; explicit LOW/MEDIUM/HIGH/CRITICAL remains a reasoned override
and never modifies the saved asset. Exposure is still a per-calculation assumption; it
is not inferred from environment, site, address or owners.

A new risk snapshot records the resolved criticality, source (`asset_context` or
`snapshot_override`), source revision, complete business-context copy (including site
name/revision), and `context_resolution_version=asset-context-v1`. The criticality ledger
identifies the actual source. The numerical formula remains `exposure-v1.0`: no weights
or confidence factors change. Environment, owners and site are context, not hidden factors.
Old risk snapshots remain unchanged and readable; context changes do not auto-recalculate
scores or rewrite historical ownership/site labels. Recalculate explicitly when needed.

The documented default resolution is a deliberate additive Epic 14 API behavior change:
clients that require the old always-unknown default can send `criticality: "UNKNOWN"`.
Existing explicit overrides and old scanner/inventory APIs remain compatible. Repeated
scanner imports cannot modify the separate business-context table.

## Operation, acceptance and deferred work

```sh
docker compose build backend worker frontend
docker compose run --rm --no-deps backend alembic upgrade head
docker compose up -d --no-build backend worker frontend
```

Use the Compose PostgreSQL connection rather than an unrelated host PostgreSQL instance.
No new secrets, environment flags or external services are required.

Created: context/site/history models, schemas, service/API, Alembic migration, business
context editor, backend/browser tests and this document. Modified: model/router registration,
risk context resolution and frontend controls, asset-detail integration, frontend API/types,
styles, shared browser fixtures, README, SPEC and roadmap.

Acceptance covers defaults/no-write reads, patch/clear/no-op behavior, audit/history,
scanner preservation, organization isolation, stale-revision conflicts, site normalization,
rename/archive/restore, historical site labels, immutable risk context, explicit override vs
inheritance, accessible editor labels/help, mobile interaction and retained conflict drafts.

Known limitations / technical debt: owners and teams are labels, not directory entities;
no RBAC actor identity, bulk edits/imports or business-context inventory filtering; one
location per asset; site listing is unpaginated; history retention is not automated.
Site changes are auditable but a standalone site-audit UI is deferred. Numerical risk policy
is unchanged and remains heuristic. No external integration or notification is performed.

Next epic only on request: **15 — Network Segmentation Assessment**.

## Verification receipt — delivery 2026-10-04 (Europe/Vienna)

- **99 backend tests passed locally and in the fresh Docker image; 11 Playwright tests passed.**
- Local/frontend and Docker backend/worker/frontend builds succeeded.
- Compose PostgreSQL is on `20261003_0012 (head)`; all five services are running.
- PostgreSQL/API transactional smoke verified site creation, context save/read, stale-revision
  rejection, site rename/archive, immutable historical labels and saved criticality inheritance.
  All smoke organizations/assets/contexts/sites/risk snapshots were rolled back; no fake
  business context remains and no scanner jobs were created.
- Live HTTP GET/history/sites/OpenAPI and cross-organization rejection passed.
- Live GUI displayed the editor, correctly associated form labels, keyboard tooltip and
  location manager without JavaScript errors. Read-only smoke did not modify actual assets.
- Existing Starlette/httpx deprecation warning remains; no known failing checks.
