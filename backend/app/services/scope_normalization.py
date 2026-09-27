import ipaddress

from app.models.scope import ScopeTargetType


def normalize_target(target: str, target_type: ScopeTargetType | None = None) -> str:
    value = target.strip().lower().rstrip(".")

    if target_type == ScopeTargetType.IP:
        return str(ipaddress.ip_address(value))

    if target_type == ScopeTargetType.CIDR:
        return str(ipaddress.ip_network(value, strict=False))

    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return value

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    return value
