from fastapi import APIRouter

from app.schemas.scanner import ScannerAdapterRead
from app.scanners.registry import scanner_registry

router = APIRouter(prefix="/scanner-adapters", tags=["scanner-adapters"])


@router.get("", response_model=list[ScannerAdapterRead])
def list_all() -> list[ScannerAdapterRead]:
    return [
        ScannerAdapterRead(
            name=adapter.name,
            display_name=adapter.display_name,
            supported_target_notes=adapter.supported_target_notes,
            execution_available=adapter.execution_supported,
        )
        for adapter in scanner_registry.list_adapters()
    ]
