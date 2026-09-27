# SignalHound Specification

SignalHound is an authorized external reconnaissance and exposure-management application.

The current implementation covers **Epic 1: Foundation** only. Later epics may add scope management, scope enforcement, inventory, scanner adapters, external discovery, findings, change detection, and a UI.

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

## Security Boundary

SignalHound is intended only for authorized security assessments. Epic 1 implements no scanning, exploitation, credential attacks, brute force functionality, payload deployment, or destructive testing.

