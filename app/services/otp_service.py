"""OTP generation, storage, and verification for one-time password login."""

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_token
from app.models.otp import OTP
from app.models.user import User
from app.schemas.auth import LoginResponse
from app.services.auth_service import AuthenticationError, create_token_pair


def _generate_otp() -> str:
	"""Return a cryptographically secure random 6-digit OTP string."""

	return str(secrets.randbelow(900_000) + 100_000)


def request_otp(database_session: Session, email: str) -> str:
	"""Validate the account, create a hashed OTP record, and return the raw OTP.

	The caller is responsible for delivering the raw OTP to the user.
	Raises ``AuthenticationError`` when the account is not eligible.
	"""

	normalized = email.lower()
	user = database_session.scalar(select(User).where(User.email == normalized))

	if user is None or not user.is_active:
		raise AuthenticationError("No active account found for that email address")

	if not user.is_verified:
		raise AuthenticationError("Email address is not verified")

	raw_otp = _generate_otp()
	expires_at = datetime.now(timezone.utc) + timedelta(
		minutes=settings.otp_expire_minutes
	)
	database_session.add(
		OTP(
			user_id=user.id,
			code_hash=hash_token(raw_otp),
			purpose="login",
			expires_at=expires_at,
		)
	)
	database_session.commit()
	return raw_otp


def verify_otp_and_login(
	database_session: Session,
	email: str,
	raw_otp: str,
) -> LoginResponse:
	"""Verify a submitted OTP and issue a JWT token pair on success.

	Raises ``AuthenticationError`` when the OTP is invalid, expired, or used.
	"""

	normalized = email.lower()
	user = database_session.scalar(select(User).where(User.email == normalized))

	if user is None or not user.is_active:
		raise AuthenticationError("Invalid OTP or email")

	stored = database_session.scalar(
		select(OTP).where(
			OTP.user_id == user.id,
			OTP.code_hash == hash_token(raw_otp),
			OTP.purpose == "login",
			OTP.consumed_at.is_(None),
		)
	)

	now = datetime.now(timezone.utc)

	if stored is None:
		raise AuthenticationError("Invalid OTP or email")

	expires_at = stored.expires_at
	if expires_at.tzinfo is None:
		expires_at = expires_at.replace(tzinfo=timezone.utc)

	if expires_at <= now:
		raise AuthenticationError("OTP has expired")

	stored.consumed_at = now
	database_session.flush()

	return create_token_pair(database_session, user)
