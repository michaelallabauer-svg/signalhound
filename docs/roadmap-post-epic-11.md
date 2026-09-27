# SignalHound Development Roadmap

## Post-Epic-11 Specification

This document extends the existing SignalHound specification after completion of Epic 11: Internal IT Recon Foundation.

SignalHound is an authorized security reconnaissance, exposure-management, and security-assessment platform.

The purpose of this roadmap is to evolve SignalHound from a reconnaissance and scanner orchestration application into an explainable, auditable Exposure Management and Security Assessment platform.

## Development Principles

- SignalHound must only operate against infrastructure explicitly authorized through its scope-management system.
- No future feature may bypass scope validation.
- Discovery of an asset does not automatically authorize active scanning.
- Discovered infrastructure may be stored as `DISCOVERED`, `UNVERIFIED`, or `OUT_OF_SCOPE`, but must not automatically become an authorized scan target.
- Historical data must be preserved so the platform can explain what existed, appeared, disappeared, changed, or was resolved at a point in time.
- Security scores and management indicators must be explainable through stored components.
- Scanner-specific logic must remain behind scanner adapters.
- Codex must implement only the Epic explicitly assigned and must not automatically begin subsequent Epics.

## Target Architecture

Long-term conceptual architecture:

```text
                         SIGNALHOUND CORE
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
   ASSET / SERVICE         ASSESSMENTS              MANAGEMENT
      INVENTORY                 |                     VIEWS
        |                 Scanner Jobs                 |
        +-----------+-----------+-----------+-----------+
                    |                       |
                    v                       v
             EXTERNAL RECON            INTERNAL IT
                    |                       |
              Amass / Nmap                 Nmap
                 Nuclei                     |
                    +-----------+-----------+
                                |
                                v
                           ENRICHMENT
                                |
                    +-----------+-----------+
                    |                       |
                   CVE                     CPE
                    |                       |
                   CVSS                    EPSS
                    |                       |
                   KEV                 Intelligence
                    |
                    v
                 FINDINGS
                    |
                    v
              EXPOSURE ENGINE
                    |
                    v
               ASSESSMENTS
                    |
                    v
           MANAGEMENT POSTURE
```

Future extensions may add distributed scanner nodes, segmentation validation, remediation workflows, threat intelligence providers, credential exposure monitoring, and OT reconnaissance.

## Epic 11.5: Production Hardening

Before expanding reconnaissance functionality, the existing SignalHound platform must undergo a production-hardening phase.

Goals:

- Improve security, resilience, isolation, and operational safety.
- Review authentication readiness without implementing Entra ID unless separately requested.
- Review API security, input validation, request-size limits, error handling, CORS, and information leakage.
- Ensure scanner execution remains shell-free and cannot accept arbitrary executable commands from API clients.
- Review worker concurrency, timeout, failed-job handling, and resource-exhaustion behavior.
- Ensure secrets do not exist in source code, scanner output, logs, audit events, Git history, or frontend bundles.
- Avoid unintentionally exposing sensitive scanner output through application logs.
- Review database least privilege, migrations, backup/restore strategy, retention, and connection security.
- Review Docker privileges, exposed ports, filesystems, writable volumes, resource limits, and network separation.

Deliverable:

- Hardening findings
- Implemented fixes
- Deferred improvements
- Tests
- Documentation changes

Do not begin Epic 12 automatically after completing Epic 11.5.

## Epic 12: Vulnerability Intelligence and Enrichment

Transform discovered software and scanner findings into enriched vulnerability intelligence.

SignalHound must distinguish between observed software, potential vulnerability, scanner-confirmed finding, and external vulnerability intelligence.

Future architecture should support provider adapters for CVE, CVSS, CPE, EPSS, KEV, and related intelligence. Provider-specific logic must not leak into core business logic.

Matching confidence must be stored separately from severity. Low-confidence version matches must not automatically become confirmed security findings.

## Epic 13: Exposure and Risk Engine

Introduce explainable prioritization of security exposure.

CVSS alone must not be treated as organizational risk. Future risk scores should include component records for CVSS, EPSS, KEV, exposure, asset criticality, finding age, and confidence. Algorithm versions must be stored.

## Epic 14: Asset Criticality, Context and Ownership

Add business context to technical assets:

- Asset criticality: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Environment: `PRODUCTION`, `TEST`, `DEVELOPMENT`, `INFRASTRUCTURE`, `UNKNOWN`
- Technical owner, organizational owner, responsible team
- Configurable site/location records

Site names must be configurable data, not hard-coded application logic.

## Epic 15: Network Segmentation Assessment

Validate intended network segmentation against observed connectivity.

This Epic must not become an unrestricted internal port-scanning mechanism. Tests must originate from explicitly authorized scanner locations and target explicitly authorized network zones.

Expected state and observed state must remain separate. Results should include `PASS`, `FAIL`, `UNEXPECTED_ACCESS`, `UNEXPECTED_BLOCK`, `NOT_TESTED`, and `ERROR`.

## Epic 16: Distributed Scanner Nodes

Allow SignalHound to execute authorized assessments from multiple network locations.

Prefer an outbound/pull model where scanner nodes request authorized jobs from SignalHound. Node communication must eventually support strong authentication, encrypted transport, node identity, job authorization, capability restrictions, revocation, heartbeat, and version reporting.

## Epic 17: Security Assessment Engine

Evolve `AssessmentRun` from grouped scanner execution into a complete security-assessment concept.

An assessment may contain scanner jobs, observations, enrichment results, findings, comparisons, and point-in-time metrics. Assessment types may include `EXTERNAL_EXPOSURE`, `INTERNAL_INFRASTRUCTURE`, and `SEGMENTATION`.

## Epic 18: Management Security Posture

Provide a non-technical management view of security exposure that prioritizes current exposure, meaningful changes, remediation progress, business relevance, and trends.

Management metrics must remain traceable down to evidence.

## Epic 19: Attack Surface Graph

Represent relationships between discovered infrastructure, such as domain to subdomain to IP to service to finding or vulnerability.

Do not introduce a graph database by default. Use PostgreSQL unless demonstrated query or performance requirements justify another technology.

## Epic 20: Reporting and Evidence

Generate reproducible security-assessment reports and preserve supporting evidence.

Reports must be reproducible from persisted data and trace findings through observations, scanner jobs, assessment runs, timestamps, and raw evidence.

## Epic 21: Remediation Workflow and Integrations

Turn findings into manageable remediation work through assignment, responsible teams, due dates, remediation SLA, comments, evidence, and reopen workflow.

External integrations must use adapters and must not tightly couple SignalHound to one ticketing system.

## Epic 22: Authentication and RBAC

Provide enterprise-grade user authentication and authorization.

Potential future authentication: Microsoft Entra ID / OpenID Connect.

Potential roles: `ADMINISTRATOR`, `SECURITY_ANALYST`, `AUDITOR`, `MANAGEMENT`, `READ_ONLY`.

## Epic 23: Scheduled Assessments

Allow recurring authorized assessments. Schedules must reference existing authorized scopes and must never bypass scope validation.

## Epic 24: Threat Intelligence Provider Framework

Prepare SignalHound for external threat-intelligence sources through provider architecture. Threat intelligence must not automatically create confirmed vulnerabilities.

## Epic 25: OT Recon Foundation

Prepare separately controlled reconnaissance architecture for OT environments.

OT reconnaissance must not reuse aggressive IT scanning profiles. Active OT scanning should remain disabled until explicitly configured and authorized.

## Recommended Implementation Sequence

```text
CURRENT STATE: Epic 1 - Epic 11
        |
        v
Epic 11.5: Production Hardening
        |
        v
Epic 12: Vulnerability Intelligence
        |
        v
Epic 13: Exposure / Risk Engine
        |
        v
Epic 14: Asset Criticality & Ownership
        |
        v
Epic 15: Segmentation Assessment
        |
        v
Epic 16: Distributed Scanner Nodes
        |
        v
Epic 17: Security Assessment Engine
        |
        v
Epic 18: Management Security Posture
        |
        v
Epic 19: Attack Surface Graph
        |
        v
Epic 20: Reporting & Evidence
        |
        v
Epic 21: Remediation Workflow
        |
        v
Epic 22: Authentication / RBAC
        |
        v
Epic 23: Scheduled Assessments
        |
        v
Epic 24: Threat Intelligence
        |
        v
Epic 25: OT Recon Foundation
```

## Codex Working Instructions

When instructed to implement an Epic:

1. Read the complete existing SignalHound specification.
2. Inspect the existing repository before making changes.
3. Determine how the requested Epic integrates with existing architecture.
4. Preserve backward compatibility unless explicitly instructed otherwise.
5. Reuse existing domain models and services where appropriate.
6. Do not duplicate functionality already present.
7. Use database migrations for schema changes.
8. Add automated tests for new behavior.
9. Update API documentation where applicable.
10. Update README documentation where operational behavior changes.
11. Update frontend functionality only where required by the Epic.
12. Preserve historical data.
13. Preserve auditability.
14. Preserve scope enforcement.
15. Do not introduce active scanning outside explicitly authorized scopes.
16. Do not implement functionality belonging to subsequent Epics.
17. Run the existing test suite before implementation.
18. Run the complete test suite after implementation.
19. Report regressions.
20. Stop after the requested Epic is complete.

## Required Completion Report

After every Epic, Codex must provide:

- Implementation summary
- Files created
- Files modified
- Database migrations
- API changes
- Frontend changes
- Security considerations
- Scope enforcement impact
- Test results
- Acceptance criteria
- Known issues
- Technical debt
- Architectural decisions
- Recommended next step

## Current Development Instruction

The current production state is Epic 11.

The next implementation target is:

```text
EPIC 11.5 - PRODUCTION HARDENING
```

Do not implement Epic 12 or later.
