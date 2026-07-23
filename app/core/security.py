"""Password hashing and JWT utilities for the authentication service."""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
	"""Hash a plaintext password with bcrypt."""

	return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
	"""Return whether a plaintext password matches a bcrypt hash."""

	return password_context.verify(plain_password, hashed_password)


def create_access_token(subject: str) -> str:
	"""Create a signed short-lived JWT access token for a subject."""

	expires_at = datetime.now(timezone.utc) + timedelta(
		minutes=settings.access_token_expire_minutes
	)
	payload = {
		"sub": subject,
		"type": "access",
		"exp": expires_at,
	}
	return jwt.encode(
		payload,
		settings.secret_key.get_secret_value(),
		algorithm=settings.jwt_algorithm,
	)


def create_refresh_token(subject: str) -> tuple[str, str, datetime]:
	"""Create a signed refresh JWT and return it with its ID and expiry."""

	token_id = secrets.token_urlsafe(24)
	expires_at = datetime.now(timezone.utc) + timedelta(
		days=settings.refresh_token_expire_days
	)
	payload = {
		"sub": subject,
		"type": "refresh",
		"jti": token_id,
		"exp": expires_at,
	}
	token = jwt.encode(
		payload,
		settings.secret_key.get_secret_value(),
		algorithm=settings.jwt_algorithm,
	)
	return token, token_id, expires_at


def decode_token(token: str) -> dict[str, Any]:
	"""Decode and validate a signed JWT, raising ``JWTError`` when invalid."""

	return jwt.decode(
		token,
		settings.secret_key.get_secret_value(),
		algorithms=[settings.jwt_algorithm],
	)


def hash_token(token: str) -> str:
	"""Return a deterministic SHA-256 digest suitable for token persistence."""

	return hashlib.sha256(token.encode("utf-8")).hexdigest()
