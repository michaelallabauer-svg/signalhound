from app.scanners.base import ScannerAdapter
from app.scanners.placeholders import AmassAdapter, NmapAdapter, NucleiAdapter


class ScannerRegistry:
    def __init__(self) -> None:
        adapters: list[ScannerAdapter] = [NmapAdapter(), AmassAdapter(), NucleiAdapter()]
        self._adapters = {adapter.name: adapter for adapter in adapters}

    def list_adapters(self) -> list[ScannerAdapter]:
        return list(self._adapters.values())

    def get(self, name: str) -> ScannerAdapter | None:
        return self._adapters.get(name)


scanner_registry = ScannerRegistry()

