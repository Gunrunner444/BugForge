"""Typed research-lead relationships.

Revision ID: 026
Revises: 025
Create Date: 2026-09-25 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("research_leads", sa.Column("hypothesis_ids", sa.JSON(), nullable=True))
    op.add_column("research_leads", sa.Column("finding_ids", sa.JSON(), nullable=True))
    op.add_column("research_leads", sa.Column("semantic_node_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("research_leads", "semantic_node_ids")
    op.drop_column("research_leads", "finding_ids")
    op.drop_column("research_leads", "hypothesis_ids")
