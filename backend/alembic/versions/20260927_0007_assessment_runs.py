"""assessment runs

Revision ID: 20260927_0007
Revises: 20260927_0006
Create Date: 2026-09-27 22:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0007"
down_revision: Union[str, None] = "20260927_0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

assessment_run_status = postgresql.ENUM(
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    name="assessment_run_status",
    create_type=False,
)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE assessment_run_status AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "assessment_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("scope_id", sa.Integer(), nullable=False),
        sa.Column("profile_name", sa.String(length=80), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("status", assessment_run_status, nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.String(length=2048), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_id"], ["scopes.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assessment_runs_organization_id"), "assessment_runs", ["organization_id"], unique=False)
    op.create_index(op.f("ix_assessment_runs_scope_id"), "assessment_runs", ["scope_id"], unique=False)
    op.create_index(op.f("ix_assessment_runs_profile_name"), "assessment_runs", ["profile_name"], unique=False)
    op.create_index(op.f("ix_assessment_runs_target"), "assessment_runs", ["target"], unique=False)

    op.add_column("scanner_jobs", sa.Column("assessment_run_id", sa.Integer(), nullable=True))
    op.create_index(op.f("ix_scanner_jobs_assessment_run_id"), "scanner_jobs", ["assessment_run_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_scanner_jobs_assessment_run_id_assessment_runs"),
        "scanner_jobs",
        "assessment_runs",
        ["assessment_run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_scanner_jobs_assessment_run_id_assessment_runs"), "scanner_jobs", type_="foreignkey")
    op.drop_index(op.f("ix_scanner_jobs_assessment_run_id"), table_name="scanner_jobs")
    op.drop_column("scanner_jobs", "assessment_run_id")
    op.drop_index(op.f("ix_assessment_runs_target"), table_name="assessment_runs")
    op.drop_index(op.f("ix_assessment_runs_profile_name"), table_name="assessment_runs")
    op.drop_index(op.f("ix_assessment_runs_scope_id"), table_name="assessment_runs")
    op.drop_index(op.f("ix_assessment_runs_organization_id"), table_name="assessment_runs")
    op.drop_table("assessment_runs")
    op.execute("DROP TYPE IF EXISTS assessment_run_status")
