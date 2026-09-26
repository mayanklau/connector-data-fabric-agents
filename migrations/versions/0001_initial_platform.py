"""Initial durable platform schema."""

from alembic import op
import sqlalchemy as sa


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("objects"):
        op.create_table(
            "objects",
            sa.Column("kind", sa.String(64), primary_key=True),
            sa.Column("id", sa.String(255), primary_key=True),
            sa.Column("payload", sa.Text(), nullable=False),
            sa.Column("created_at", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.String(64), nullable=False),
        )
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("objects")}
    if "ix_objects_kind_created" not in indexes:
        op.create_index("ix_objects_kind_created", "objects", ["kind", "created_at"])
    if not inspector.has_table("workflows"):
        op.create_table(
            "workflows",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("event_id", sa.String(64), nullable=False),
            sa.Column("idempotency_key", sa.String(255), unique=True, nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("result_case_id", sa.String(64)),
            sa.Column("error", sa.Text()),
            sa.Column("created_at", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.String(64), nullable=False),
        )
    if not inspector.has_table("telemetry"):
        op.create_table(
            "telemetry",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("trace_id", sa.String(64), nullable=False),
            sa.Column("span", sa.String(255), nullable=False),
            sa.Column("duration_ms", sa.Float(), nullable=False),
            sa.Column("attributes", sa.Text(), nullable=False),
            sa.Column("created_at", sa.String(64), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("telemetry")
    op.drop_table("workflows")
    op.drop_index("ix_objects_kind_created", table_name="objects")
    op.drop_table("objects")
