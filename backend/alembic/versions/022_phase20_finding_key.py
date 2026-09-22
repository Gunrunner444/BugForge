"""Phase 20 persistent finding identity.

Revision ID: 022
Revises: 021
Create Date: 2026-09-22 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.repositories.finding_identity import FindingKeyRecord, canonicalize_finding_key_rows

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("security_findings", sa.Column("finding_key", sa.Text(), nullable=True))
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, project_id, created_at, intelligence_json FROM security_findings"
        )
    )
    records = [
        FindingKeyRecord(
            id=row[0],
            project_id=row[1],
            created_at=row[2],
            intelligence_json=row[3] or "{}",
            finding_key=None,
        )
        for row in rows
    ]
    for updated in canonicalize_finding_key_rows(records):
        conn.execute(
            sa.text(
                "UPDATE security_findings "
                "SET finding_key = :key, intelligence_json = :intel "
                "WHERE id = :id"
            ),
            {
                "key": updated.finding_key,
                "intel": updated.intelligence_json,
                "id": updated.id,
            },
        )
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
