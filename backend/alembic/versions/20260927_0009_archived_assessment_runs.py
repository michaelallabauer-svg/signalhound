"""archived assessment runs

Revision ID: 20260927_0009
Revises: 20260927_0008
Create Date: 2026-09-27 23:45:00.000000

"""
from typing import Sequence, Union

from alembic import op

revision: str = "20260927_0009"
down_revision: Union[str, None] = "20260927_0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE assessment_run_status ADD VALUE IF NOT EXISTS 'ARCHIVED'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely without recreating dependent columns.
    pass
