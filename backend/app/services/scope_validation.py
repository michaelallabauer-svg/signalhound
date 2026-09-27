import ipaddress
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.scope import ScanZone, Scope, ScopeTargetType
from app.repositories.scopes import find_active_scopes
from app.services.audit import record_audit_event
from app.services.scope_normalization import normalize_target


@dataclass(frozen=True)
class ScopeValidationResult:
    target: str
    normalized_target: str
    allowed: bool
    scope_id: int | None
    reason: str


class ScopeValidator:
    def validate(
        self,
        db: Session,
        *,
        organization_id: int,
        target: str,
        scan_zone: ScanZone = ScanZone.EXTERNAL,
    ) -> ScopeValidationResult:
        normalized_target = normalize_target(target)
        scopes = find_active_scopes(
            db,
            organization_id=organization_id,
            scan_zone=scan_zone,
        )

        for scope in scopes:
            if self._matches(scope, normalized_target):
                result = ScopeValidationResult(
                    target=target,
                    normalized_target=normalized_target,
                    allowed=True,
                    scope_id=scope.id,
                    reason="target matched active scope",
                )
                self._audit(db, organization_id, result)
                return result

        result = ScopeValidationResult(
            target=target,
            normalized_target=normalized_target,
            allowed=False,
            scope_id=None,
            reason="target did not match any active scope",
        )
        self._audit(db, organization_id, result)
        return result

    def _matches(self, scope: Scope, normalized_target: str) -> bool:
        if scope.target_type == ScopeTargetType.DOMAIN:
            return normalized_target == scope.target or normalized_target.endswith(f".{scope.target}")

        if scope.target_type == ScopeTargetType.HOSTNAME:
            return normalized_target == scope.target

        if scope.target_type == ScopeTargetType.IP:
            try:
                return ipaddress.ip_address(normalized_target) == ipaddress.ip_address(scope.target)
            except ValueError:
                return False

        if scope.target_type == ScopeTargetType.CIDR:
            try:
                return ipaddress.ip_address(normalized_target) in ipaddress.ip_network(scope.target)
            except ValueError:
                return False

        return False

    def _audit(
        self,
        db: Session,
        organization_id: int,
        result: ScopeValidationResult,
    ) -> None:
        record_audit_event(
            db,
            action="scope.validation.approved" if result.allowed else "scope.validation.rejected",
            affected_object_type="target",
            affected_object_id=result.normalized_target,
            result="approved" if result.allowed else "rejected",
            metadata={
                "organization_id": organization_id,
                "scope_id": result.scope_id,
                "reason": result.reason,
            },
        )

