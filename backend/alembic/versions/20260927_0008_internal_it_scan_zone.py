"""internal it scan zone

Revision ID: 20260927_0008
Revises: 20260927_0007
Create Date: 2026-09-27 23:15:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = "20260927_0008"
down_revision: Union[str, None] = "20260927_0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE scan_zone ADD VALUE IF NOT EXISTS 'INTERNAL_IT'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely without recreating dependent columns.
    pass
