"""add agent rate limits and api key last_seen

Revision ID: d7b3a9f4c1e2
Revises: c5a8f1d2e4b7
Create Date: 2026-03-05 23:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7b3a9f4c1e2'
down_revision: Union[str, Sequence[str], None] = 'c5a8f1d2e4b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'agent_rate_limits',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('api_key_id', sa.Integer(), nullable=False),
        sa.Column('window_start', sa.DateTime(), nullable=False),
        sa.Column('request_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['api_key_id'], ['api_keys.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('api_key_id', 'window_start', name='uq_agent_rate_limits_key_window'),
    )
    op.create_index(op.f('ix_agent_rate_limits_api_key_id'), 'agent_rate_limits', ['api_key_id'], unique=False)
    op.create_index(op.f('ix_agent_rate_limits_window_start'), 'agent_rate_limits', ['window_start'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_agent_rate_limits_window_start'), table_name='agent_rate_limits')
    op.drop_index(op.f('ix_agent_rate_limits_api_key_id'), table_name='agent_rate_limits')
    op.drop_table('agent_rate_limits')
