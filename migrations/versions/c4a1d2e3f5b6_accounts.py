"""accounts: sign-in, sessions, saved scans, hashed API keys

Revision ID: c4a1d2e3f5b6
Revises: 95d3fe74163a
Create Date: 2026-10-20 19:30:00

"""
import hashlib
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c4a1d2e3f5b6"
down_revision: Union[str, Sequence[str], None] = "95d3fe74163a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as b:
        b.add_column(sa.Column("name", sa.String(length=255), nullable=True))
        b.add_column(sa.Column("avatar_url", sa.String(length=512), nullable=True))
        b.add_column(sa.Column("github_id", sa.String(length=32), nullable=True))
        b.add_column(sa.Column("api_key_hash", sa.String(length=64), nullable=True))
        b.add_column(sa.Column("api_key_last4", sa.String(length=8), nullable=True))
        b.add_column(sa.Column("stripe_subscription_id", sa.String(length=128), nullable=True))
        b.add_column(sa.Column("current_period_end", sa.DateTime(), nullable=True))
        b.add_column(sa.Column("rule_settings", sa.JSON(), nullable=True))
        b.alter_column("api_key", existing_type=sa.String(length=128), nullable=True)
        b.create_index(b.f("ix_users_github_id"), ["github_id"], unique=True)
        b.create_index(b.f("ix_users_api_key_hash"), ["api_key_hash"], unique=True)

    # Hash existing plaintext API keys (they keep working), then clear the plaintext.
    conn = op.get_bind()
    users = sa.table("users", sa.column("id", sa.Uuid()), sa.column("api_key", sa.String),
                     sa.column("api_key_hash", sa.String), sa.column("api_key_last4", sa.String))
    for uid, key in conn.execute(sa.select(users.c.id, users.c.api_key).where(users.c.api_key.isnot(None))).fetchall():
        conn.execute(users.update().where(users.c.id == uid).values(
            api_key_hash=hashlib.sha256(key.encode()).hexdigest(), api_key_last4=key[-4:], api_key=None))

    with op.batch_alter_table("audit_logs", schema=None) as b:
        b.create_index(b.f("ix_audit_logs_timestamp"), ["timestamp"], unique=False)

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("sessions", schema=None) as b:
        b.create_index(b.f("ix_sessions_token_hash"), ["token_hash"], unique=True)
        b.create_index(b.f("ix_sessions_user_id"), ["user_id"], unique=False)

    op.create_table(
        "login_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("login_tokens", schema=None) as b:
        b.create_index(b.f("ix_login_tokens_token_hash"), ["token_hash"], unique=True)
        b.create_index(b.f("ix_login_tokens_email"), ["email"], unique=False)
        b.create_index(b.f("ix_login_tokens_ip"), ["ip"], unique=False)
        b.create_index(b.f("ix_login_tokens_created_at"), ["created_at"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("grade", sa.String(length=2), nullable=False),
        sa.Column("resource_count", sa.Integer(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=True),
        sa.Column("share_id", sa.String(length=40), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scans", schema=None) as b:
        b.create_index(b.f("ix_scans_user_id"), ["user_id"], unique=False)
        b.create_index(b.f("ix_scans_share_id"), ["share_id"], unique=True)
        b.create_index(b.f("ix_scans_created_at"), ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("scans")
    op.drop_table("login_tokens")
    op.drop_table("sessions")
    with op.batch_alter_table("audit_logs", schema=None) as b:
        b.drop_index(b.f("ix_audit_logs_timestamp"))
    with op.batch_alter_table("users", schema=None) as b:
        b.drop_index(b.f("ix_users_api_key_hash"))
        b.drop_index(b.f("ix_users_github_id"))
        for col in ("rule_settings", "current_period_end", "stripe_subscription_id", "api_key_last4",
                    "api_key_hash", "github_id", "avatar_url", "name"):
            b.drop_column(col)
