"""Business logic for registration, login, and refresh-token rotation."""

from datetime import datetime, timezone
from uuid import UUID

from jose import JWTError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
	create_access_token,
	create_refresh_token,
	decode_token,
	hash_password,
	hash_token,
	verify_password,
)
from app.models.token import Token
from app.models.user import User
from app.schemas.auth import CredentialsRequest, LoginResponse


class AuthenticationError(ValueError):
	"""Represent an authentication or token lifecycle failure."""


def register_user(database_session: Session, credentials: CredentialsRequest) -> User:
	"""Create and persist a user from validated registration credentials."""

	normalized_email = str(credentials.email).lower()
	existing_user = database_session.scalar(
		select(User).where(User.email == normalized_email)
	)
	if existing_user is not None:
		raise AuthenticationError("Email is already registered")

	user = User(
		email=normalized_email,
		hashed_password=hash_password(credentials.password),
	)
	database_session.add(user)
	try:
		database_session.commit()
	except IntegrityError as error:
		database_session.rollback()
		raise AuthenticationError("Email is already registered") from error
	database_session.refresh(user)
	return user


def authenticate_user(
	database_session: Session,
	credentials: CredentialsRequest,
) -> User:
	"""Verify credentials and return the active matching user."""

	normalized_email = str(credentials.email).lower()
	user = database_session.scalar(select(User).where(User.email == normalized_email))
	if (
		user is None
		or user.hashed_password is None
		or not verify_password(credentials.password, user.hashed_password)
		or not user.is_active
	):
		raise AuthenticationError("Invalid email or password")
	return user


def _issue_token_pair(database_session: Session, user: User) -> LoginResponse:
	"""Create access and refresh tokens and persist the refresh-token digest."""

	access_token = create_access_token(str(user.id))
	refresh_token, _, refresh_expires_at = create_refresh_token(str(user.id))
	database_session.add(
		Token(
			user_id=user.id,
			token_hash=hash_token(refresh_token),
			token_type="refresh",
			expires_at=refresh_expires_at,
		)
	)
	return LoginResponse(
		access_token=access_token,
		refresh_token=refresh_token,
	)


def create_token_pair(database_session: Session, user: User) -> LoginResponse:
	"""Issue and persist a token pair for a successfully authenticated user."""

	token_pair = _issue_token_pair(database_session, user)
	database_session.commit()
	return token_pair


def rotate_refresh_token(database_session: Session, refresh_token: str) -> LoginResponse:
	"""Revoke a valid refresh token and atomically issue its replacement."""

	try:
		claims = decode_token(refresh_token)
	except JWTError as error:
		raise AuthenticationError("Invalid or expired refresh token") from error

	subject = claims.get("sub")
	if claims.get("type") != "refresh" or not subject:
		raise AuthenticationError("Invalid refresh token")

	try:
		user_id = UUID(subject)
	except (TypeError, ValueError) as error:
		raise AuthenticationError("Invalid refresh token") from error

	stored_token = database_session.scalar(
		select(Token).where(
			Token.token_hash == hash_token(refresh_token),
			Token.token_type == "refresh",
			Token.revoked_at.is_(None),
		)
	)
	now = datetime.now(timezone.utc)
	if stored_token is None:
		raise AuthenticationError("Invalid or expired refresh token")

	expires_at = stored_token.expires_at
	if expires_at.tzinfo is None:
		expires_at = expires_at.replace(tzinfo=timezone.utc)
	if expires_at <= now:
		raise AuthenticationError("Invalid or expired refresh token")

	user = database_session.get(User, user_id)
	if user is None or not user.is_active:
		raise AuthenticationError("User is not available")

	stored_token.revoked_at = now
	token_pair = _issue_token_pair(database_session, user)
	database_session.commit()
	return token_pair
