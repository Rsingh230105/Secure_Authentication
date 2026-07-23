"""User persistence model for authentication and account state."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
	from app.models.otp import OTP
	from app.models.token import Token


class User(Base):
	"""Represent a registered user and the user's account state."""

	__tablename__ = "users"

	id: Mapped[UUID] = mapped_column(
		PostgreSQLUUID(as_uuid=True),
		primary_key=True,
		default=uuid4,
	)
	email: Mapped[str] = mapped_column(
		String(320),
		unique=True,
		index=True,
		nullable=False,
	)
	hashed_password: Mapped[str | None] = mapped_column(
		String(255),
		nullable=True,
	)
	is_active: Mapped[bool] = mapped_column(
		Boolean,
		default=True,
		nullable=False,
	)
	is_verified: Mapped[bool] = mapped_column(
		Boolean,
		default=False,
		nullable=False,
	)
	is_superuser: Mapped[bool] = mapped_column(
		Boolean,
		default=False,
		nullable=False,
	)
	created_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		server_default=func.now(),
		nullable=False,
	)
	updated_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		server_default=func.now(),
		onupdate=func.now(),
		nullable=False,
	)

	tokens: Mapped[list["Token"]] = relationship(
		"Token",
		back_populates="user",
		cascade="all, delete-orphan",
	)
	otps: Mapped[list["OTP"]] = relationship(
		"OTP",
		back_populates="user",
		cascade="all, delete-orphan",
	)
