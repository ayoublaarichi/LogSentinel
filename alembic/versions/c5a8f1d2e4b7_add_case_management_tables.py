"""add case management tables

Revision ID: c5a8f1d2e4b7
Revises: 9fcec7e90272
Create Date: 2026-03-05 23:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c5a8f1d2e4b7'
down_revision: Union[str, Sequence[str], None] = '9fcec7e90272'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cases',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('priority', sa.String(length=32), nullable=False),
        sa.Column('owner', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cases_priority'), 'cases', ['priority'], unique=False)
    op.create_index(op.f('ix_cases_project_id'), 'cases', ['project_id'], unique=False)
    op.create_index(op.f('ix_cases_status'), 'cases', ['status'], unique=False)
    op.create_index(op.f('ix_cases_user_id'), 'cases', ['user_id'], unique=False)

    op.create_table(
        'case_activities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('actor', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_activities_case_id'), 'case_activities', ['case_id'], unique=False)

    op.create_table(
        'case_alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'alert_id', name='uq_case_alerts_case_alert'),
    )
    op.create_index(op.f('ix_case_alerts_alert_id'), 'case_alerts', ['alert_id'], unique=False)
    op.create_index(op.f('ix_case_alerts_case_id'), 'case_alerts', ['case_id'], unique=False)

    op.create_table(
        'case_chain_snapshots',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('chain_id', sa.String(length=255), nullable=False),
        sa.Column('entity_type', sa.String(length=64), nullable=False),
        sa.Column('entity_value', sa.String(length=255), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('confidence', sa.String(length=32), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_chain_snapshots_case_id'), 'case_chain_snapshots', ['case_id'], unique=False)

    op.create_table(
        'case_notes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('author', sa.String(length=255), nullable=True),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_notes_case_id'), 'case_notes', ['case_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_case_notes_case_id'), table_name='case_notes')
    op.drop_table('case_notes')

    op.drop_index(op.f('ix_case_chain_snapshots_case_id'), table_name='case_chain_snapshots')
    op.drop_table('case_chain_snapshots')

    op.drop_index(op.f('ix_case_alerts_case_id'), table_name='case_alerts')
    op.drop_index(op.f('ix_case_alerts_alert_id'), table_name='case_alerts')
    op.drop_table('case_alerts')

    op.drop_index(op.f('ix_case_activities_case_id'), table_name='case_activities')
    op.drop_table('case_activities')

    op.drop_index(op.f('ix_cases_user_id'), table_name='cases')
    op.drop_index(op.f('ix_cases_status'), table_name='cases')
    op.drop_index(op.f('ix_cases_project_id'), table_name='cases')
    op.drop_index(op.f('ix_cases_priority'), table_name='cases')
    op.drop_table('cases')
