"""add projects and project scoping

Revision ID: 9fcec7e90272
Revises: 262ee7c00575
Create Date: 2026-03-04 22:22:54.471474

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9fcec7e90272'
down_revision: Union[str, Sequence[str], None] = '262ee7c00575'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    dialect = bind.dialect.name

    op.create_table('projects',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'name', name='uq_projects_user_name')
    )
    op.create_index(op.f('ix_projects_user_id'), 'projects', ['user_id'], unique=False)

    op.add_column('alerts', sa.Column('project_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_alerts_project_id'), 'alerts', ['project_id'], unique=False)

    op.add_column('api_keys', sa.Column('project_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_api_keys_project_id'), 'api_keys', ['project_id'], unique=False)

    op.add_column('audit_logs', sa.Column('project_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_audit_logs_project_id'), 'audit_logs', ['project_id'], unique=False)

    op.add_column('log_events', sa.Column('project_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_log_events_project_id'), 'log_events', ['project_id'], unique=False)

    if dialect != 'sqlite':
        op.create_foreign_key(
            'fk_alerts_project_id_projects',
            'alerts',
            'projects',
            ['project_id'],
            ['id'],
            ondelete='SET NULL',
        )
        op.create_foreign_key(
            'fk_api_keys_project_id_projects',
            'api_keys',
            'projects',
            ['project_id'],
            ['id'],
            ondelete='SET NULL',
        )
        op.create_foreign_key(
            'fk_audit_logs_project_id_projects',
            'audit_logs',
            'projects',
            ['project_id'],
            ['id'],
            ondelete='SET NULL',
        )
        op.create_foreign_key(
            'fk_log_events_project_id_projects',
            'log_events',
            'projects',
            ['project_id'],
            ['id'],
            ondelete='SET NULL',
        )


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect != 'sqlite':
        op.drop_constraint('fk_log_events_project_id_projects', 'log_events', type_='foreignkey')
        op.drop_constraint('fk_audit_logs_project_id_projects', 'audit_logs', type_='foreignkey')
        op.drop_constraint('fk_api_keys_project_id_projects', 'api_keys', type_='foreignkey')
        op.drop_constraint('fk_alerts_project_id_projects', 'alerts', type_='foreignkey')

    op.drop_index(op.f('ix_log_events_project_id'), table_name='log_events')
    op.drop_column('log_events', 'project_id')
    op.drop_index(op.f('ix_audit_logs_project_id'), table_name='audit_logs')
    op.drop_column('audit_logs', 'project_id')
    op.drop_index(op.f('ix_api_keys_project_id'), table_name='api_keys')
    op.drop_column('api_keys', 'project_id')
    op.drop_index(op.f('ix_alerts_project_id'), table_name='alerts')
    op.drop_column('alerts', 'project_id')
    op.drop_index(op.f('ix_projects_user_id'), table_name='projects')
    op.drop_table('projects')
