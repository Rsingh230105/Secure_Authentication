"""Persistent token state used by the authentication lifecycle."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
	from app.models.user import User


class Token(Base):
	"""Represent a hashed token associated with one user account."""

	__tablename__ = "tokens"

	id: Mapped[UUID] = mapped_column(
		PostgreSQLUUID(as_uuid=True),
		primary_key=True,
		default=uuid4,
	)
	user_id: Mapped[UUID] = mapped_column(
		PostgreSQLUUID(as_uuid=True),
		ForeignKey("users.id", ondelete="CASCADE"),
		index=True,
		nullable=False,
	)
	token_hash: Mapped[str] = mapped_column(
		String(255),
		unique=True,
		index=True,
		nullable=False,
	)
	token_type: Mapped[str] = mapped_column(
		String(32),
		nullable=False,
	)
	expires_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		nullable=False,
	)
	revoked_at: Mapped[datetime | None] = mapped_column(
		DateTime(timezone=True),
		nullable=True,
	)
	created_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		server_default=func.now(),
		nullable=False,
	)

	user: Mapped["User"] = relationship(
		"User",
		back_populates="tokens",
	)
