"""Versioned exposure and risk snapshots.

Revision ID: 20261003_0011
Revises: 20261003_0010
"""
from alembic import op
import sqlalchemy as sa
revision = '20261003_0011'
down_revision = '20261003_0010'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('risk_snapshots',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('algorithm_version', sa.String(40), nullable=False),
        sa.Column('context', sa.JSON(), nullable=False),
        sa.Column('result', sa.JSON(), nullable=False))
    op.create_index('ix_risk_snapshots_asset_id', 'risk_snapshots', ['asset_id'])


def downgrade():
    op.drop_table('risk_snapshots')
