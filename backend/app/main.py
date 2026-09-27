from fastapi import FastAPI

from app.api.health import router as health_router
from app.api.organizations import router as organizations_router
from app.api.scopes import router as scopes_router
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

    logger.info(
        "application_created",
        extra={"app_name": settings.app_name, "environment": settings.environment},
    )
    return app


app = create_app()
