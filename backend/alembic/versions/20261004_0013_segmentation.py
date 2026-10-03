"""Scoped segmentation rules and independent check evidence.

Revision ID: 20261004_0013
Revises: 20261003_0012
"""
from alembic import op
import sqlalchemy as sa
revision = '20261004_0013'
down_revision = '20261003_0012'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('segmentation_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('source_id', sa.String(80), nullable=False),
        sa.Column('source', sa.JSON(), nullable=False),
        sa.Column('scope_id', sa.Integer(), sa.ForeignKey('scopes.id'), nullable=False),
        sa.Column('zone', sa.JSON(), nullable=False),
        sa.Column('target', sa.String(45), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('expected', sa.String(10), nullable=False),
        sa.Column('rationale', sa.String(2000), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("expected IN ('ALLOW','DENY')", name='ck_segmentation_expected'),
        sa.CheckConstraint('port >= 1 AND port <= 65535', name='ck_segmentation_port'))
    op.create_index('ix_segmentation_rules_organization_id', 'segmentation_rules', ['organization_id'])
    op.create_table('segmentation_checks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('rule_id', sa.Integer(), sa.ForeignKey('segmentation_rules.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('outcome', sa.String(30), nullable=False),
        sa.Column('expected', sa.JSON(), nullable=False),
        sa.Column('observed', sa.JSON(), nullable=False),
        sa.CheckConstraint("status IN ('PASS','FAIL','NOT_TESTED','ERROR')", name='ck_segmentation_status'),
        sa.CheckConstraint("outcome IN ('PASS','UNEXPECTED_ACCESS','UNEXPECTED_BLOCK','NOT_TESTED','ERROR')", name='ck_segmentation_outcome'))
    op.create_index('ix_segmentation_checks_rule_id', 'segmentation_checks', ['rule_id'])


def downgrade():
    op.drop_table('segmentation_checks')
    op.drop_table('segmentation_rules')
