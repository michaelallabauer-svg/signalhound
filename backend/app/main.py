from fastapi import FastAPI

from app.api.assets import router as assets_router
from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.organizations import router as organizations_router
from app.api.scanner_adapters import router as scanner_adapters_router
from app.api.scanner_jobs import router as scanner_jobs_router
from app.api.scopes import router as scopes_router
from app.api.services import router as services_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger(__name__)

    app = FastAPI(title=settings.app_name)
    app.include_router(health_router)
    app.include_router(organizations_router, prefix="/api/v1")
    app.include_router(scopes_router, prefix="/api/v1")
    app.include_router(assets_router, prefix="/api/v1")
    app.include_router(services_router, prefix="/api/v1")
    app.include_router(findings_router, prefix="/api/v1")
    app.include_router(scanner_adapters_router, prefix="/api/v1")
    app.include_router(scanner_jobs_router, prefix="/api/v1")

    logger.info(
        "application_created",
        extra={"app_name": settings.app_name, "environment": settings.environment},
    )
    return app


app = create_app()
