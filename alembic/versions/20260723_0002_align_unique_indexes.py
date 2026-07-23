"""Align unique indexes with SQLAlchemy model declarations.

Revision ID: 20260723_0002
Revises: 20260723_0001
Create Date: 2026-07-23
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260723_0002"
down_revision: Union[str, Sequence[str], None] = "20260723_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Replace table constraints with unique indexes matching the models."""

    op.drop_constraint("users_email_key", "users", type_="unique")
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.drop_constraint("tokens_token_hash_key", "tokens", type_="unique")
    op.drop_index("ix_tokens_token_hash", table_name="tokens")
    op.create_index("ix_tokens_token_hash", "tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    """Restore table constraints and non-unique indexes."""

    op.drop_index("ix_tokens_token_hash", table_name="tokens")
    op.create_index("ix_tokens_token_hash", "tokens", ["token_hash"], unique=False)
    op.create_unique_constraint("tokens_token_hash_key", "tokens", ["token_hash"])

    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_unique_constraint("users_email_key", "users", ["email"])
