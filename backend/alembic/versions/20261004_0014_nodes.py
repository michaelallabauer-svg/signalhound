"""Authenticated pull nodes and bounded job leases.
Revision ID: 20261004_0014
Revises: 20261004_0013
"""
from alembic import op
import sqlalchemy as sa
revision = '20261004_0014'
down_revision = '20261004_0013'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('scanner_nodes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('bind_ip', sa.String(45), nullable=False),
        sa.Column('target_scope_ids', sa.JSON(), nullable=False),
        sa.Column('target_networks', sa.JSON(), nullable=False),
        sa.Column('allowed_ports', sa.JSON(), nullable=False),
        sa.Column('capabilities', sa.JSON(), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('credential_generation', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True)),
        sa.Column('version', sa.String(40)),
        sa.Column('reported_capabilities', sa.JSON(), nullable=False),
        sa.Column('execution_enabled', sa.Boolean(), nullable=False))
    op.create_index('ix_scanner_nodes_organization_id', 'scanner_nodes', ['organization_id'])
    op.create_table('node_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('node_id', sa.Integer(), sa.ForeignKey('scanner_nodes.id'), nullable=False),
        sa.Column('rule_id', sa.Integer(), sa.ForeignKey('segmentation_rules.id'), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('expected', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('lease_hash', sa.String(64)),
        sa.Column('check_id', sa.Integer(), sa.ForeignKey('segmentation_checks.id'), unique=True),
        sa.Column('result_hash', sa.String(64)),
        sa.Column('message', sa.String(400)),
        sa.CheckConstraint("status IN ('QUEUED','LEASED','RUNNING','COMPLETED','CANCELLED','EXPIRED')", name='ck_node_job_status'))
    op.create_index('ix_node_jobs_node_id', 'node_jobs', ['node_id'])
    op.create_index('ix_node_jobs_rule_id', 'node_jobs', ['rule_id'])


def downgrade():
    op.drop_table('node_jobs')
    op.drop_table('scanner_nodes')
