"""Persistent asset business context and configurable sites.

Revision ID: 20261003_0012
Revises: 20261003_0011
"""
from alembic import op
import sqlalchemy as sa
revision = '20261003_0012'
down_revision = '20261003_0011'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('sites',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('name_key', sa.String(640), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('organization_id', 'name_key', name='uq_sites_org_name'))
    op.create_index('ix_sites_organization_id', 'sites', ['organization_id'])
    op.create_table('asset_business_contexts',
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), primary_key=True),
        sa.Column('criticality', sa.String(20)),
        sa.Column('environment', sa.String(20), nullable=False),
        sa.Column('technical_owner', sa.String(160)),
        sa.Column('organizational_owner', sa.String(160)),
        sa.Column('responsible_team', sa.String(160)),
        sa.Column('site_id', sa.Integer(), sa.ForeignKey('sites.id')),
        sa.Column('notes', sa.Text()),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("criticality IS NULL OR criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')", name='ck_asset_context_criticality'),
        sa.CheckConstraint("environment IN ('PRODUCTION','TEST','DEVELOPMENT','INFRASTRUCTURE','UNKNOWN')", name='ck_asset_context_environment'))
    op.create_index('ix_asset_business_contexts_site_id', 'asset_business_contexts', ['site_id'])
    op.create_table('asset_context_history',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('changed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('before', sa.JSON(), nullable=False),
        sa.Column('after', sa.JSON(), nullable=False),
        sa.UniqueConstraint('asset_id', 'revision', name='uq_asset_context_revision'))
    op.create_index('ix_asset_context_history_asset_id', 'asset_context_history', ['asset_id'])


def downgrade():
    op.drop_table('asset_context_history')
    op.drop_table('asset_business_contexts')
    op.drop_table('sites')
