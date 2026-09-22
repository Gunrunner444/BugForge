"""Phase 20 persistent finding identity.

Revision ID: 022
Revises: 021
Create Date: 2026-09-22 00:00:00.000000
"""

import json
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("security_findings", sa.Column("finding_key", sa.Text(), nullable=True))
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, intelligence_json FROM security_findings"))
    for row in rows:
        try:
            loaded = json.loads(row[1] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            loaded = {}
        key = ""
        if isinstance(loaded, dict):
            key = str(loaded.get("finding_key") or "")
        if key:
            conn.execute(
                sa.text("UPDATE security_findings SET finding_key = :key WHERE id = :id"),
                {"key": key, "id": row[0]},
            )
    result = conn.execute(
        sa.text(
            "SELECT id, project_id, finding_key FROM security_findings "
            "WHERE finding_key IS NOT NULL ORDER BY created_at ASC"
        )
    )
    seen: set[tuple[object, str]] = set()
    for row in result:
        pair = (row[1], row[2])
        if pair in seen:
            conn.execute(
                sa.text("UPDATE security_findings SET finding_key = NULL WHERE id = :id"),
                {"id": row[0]},
            )
        else:
            seen.add(pair)
    op.create_index(
        "ix_security_findings_finding_key",
        "security_findings",
        ["finding_key"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_security_findings_project_finding_key",
        "security_findings",
        ["project_id", "finding_key"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_security_findings_project_finding_key", "security_findings", type_="unique"
    )
    op.drop_index("ix_security_findings_finding_key", table_name="security_findings")
    op.drop_column("security_findings", "finding_key")
