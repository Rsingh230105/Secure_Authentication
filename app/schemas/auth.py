"""Request and response schemas for registration and login."""

from pydantic import BaseModel, EmailStr, Field, field_validator
from uuid import UUID


class CredentialsRequest(BaseModel):
	"""Validate email and password credentials supplied by a client."""

	email: EmailStr
	password: str = Field(min_length=8, max_length=128)

	@field_validator("password")
	@classmethod
	def validate_password_strength(cls, value: str) -> str:
		"""Require upper, lower, numeric, and special password characters."""

		requirements = (
			any(character.islower() for character in value),
			any(character.isupper() for character in value),
			any(character.isdigit() for character in value),
			any(not character.isalnum() for character in value),
		)
		if not all(requirements):
			raise ValueError(
				"Password must contain lower, upper, numeric, and special characters"
			)
		return value


class RegistrationResponse(BaseModel):
	"""Expose the public identity fields returned after registration."""

	id: UUID
	email: EmailStr
	is_active: bool
	is_verified: bool


class LoginResponse(BaseModel):
	"""Return access and refresh credentials after successful login."""

	access_token: str
	refresh_token: str
	token_type: str = "bearer"
