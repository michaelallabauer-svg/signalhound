import ipaddress

from app.models.asset import AssetType


def normalize_asset_value(value: str, asset_type: AssetType) -> str:
    normalized = value.strip().lower().rstrip(".")

    if asset_type == AssetType.IP:
        return str(ipaddress.ip_address(normalized))

    return normalized

