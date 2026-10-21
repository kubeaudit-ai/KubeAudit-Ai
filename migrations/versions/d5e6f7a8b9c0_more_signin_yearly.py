"""Google and Microsoft sign-in IDs; billing interval

Revision ID: d5e6f7a8b9c0
Revises: c4a1d2e3f5b6
Create Date: 2026-10-20 22:20:00

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, Sequence[str], None] = "c4a1d2e3f5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.add_column(sa.Column("google_id", sa.String(length=64), nullable=True))
        b.add_column(sa.Column("microsoft_id", sa.String(length=96), nullable=True))
        b.add_column(sa.Column("billing_interval", sa.String(length=8), nullable=True))
        b.create_index(b.f("ix_users_google_id"), ["google_id"], unique=True)
        b.create_index(b.f("ix_users_microsoft_id"), ["microsoft_id"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.drop_index(b.f("ix_users_microsoft_id"))
        b.drop_index(b.f("ix_users_google_id"))
        b.drop_column("billing_interval")
        b.drop_column("microsoft_id")
        b.drop_column("google_id")
