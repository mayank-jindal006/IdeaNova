"""Persist canonical scanner status and advisory metadata.

Revision ID: 0002_scanner_contract_fields
Revises: 0001_initial_contract
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_scanner_contract_fields"
down_revision = "0001_initial_contract"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sqlite = op.get_bind().dialect.name == "sqlite"
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    text_array = sa.JSON().with_variant(postgresql.ARRAY(sa.Text()), "postgresql")
    op.add_column("scans", sa.Column("scanner_status", json_type, nullable=True))
    op.add_column("findings", sa.Column("scanner", sa.String(), nullable=False, server_default="unknown"))
    op.add_column("findings", sa.Column("affected_versions", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("advisory_id", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("aliases", text_array, nullable=False, server_default="[]" if sqlite else "{}"))
    op.add_column("findings", sa.Column("references", text_array, nullable=False, server_default="[]" if sqlite else "{}"))
    op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("severity", existing_type=sa.Enum("critical", "high", "medium", "low", name="severity"), nullable=True)
        batch.alter_column("scanner", server_default=None)
        batch.alter_column("aliases", server_default=None)
        batch.alter_column("references", server_default=None)


def downgrade() -> None:
    connection = op.get_bind()
    null_severity_count = connection.execute(sa.text("SELECT count(*) FROM findings WHERE severity IS NULL")).scalar_one()
    if null_severity_count:
        raise RuntimeError(
            "Cannot downgrade scanner contract while findings with unknown severity exist; "
            "migrate or remove those rows explicitly before downgrade."
        )
    op.alter_column("findings", "severity", existing_type=sa.Enum("critical", "high", "medium", "low", name="severity"), nullable=False)
    for column in ("cvss_score", "references", "aliases", "advisory_id", "affected_versions", "scanner"):
        op.drop_column("findings", column)
    op.drop_column("scans", "scanner_status")
