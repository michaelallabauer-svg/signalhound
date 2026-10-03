from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.audit_log import AuditLog  # noqa: E402, F401
from app.models.assessment import AssessmentRun  # noqa: E402, F401
from app.models.asset import Asset, AssetObservation  # noqa: E402, F401
from app.models.change import ChangeEvent, ChangeSet  # noqa: E402, F401
from app.models.finding import Finding, FindingObservation  # noqa: E402, F401
from app.models.organization import Organization  # noqa: E402, F401
from app.models.scanner_job import ScannerJob  # noqa: E402, F401
from app.models.scope import Scope  # noqa: E402, F401
from app.models.service import Service, ServiceObservation  # noqa: E402, F401
from app.models.intelligence import IntelligenceRun, IntelligenceCache  # noqa: E402, F401
