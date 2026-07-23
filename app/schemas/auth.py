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


class MessageResponse(BaseModel):
	"""Return a plain status message for operations that produce no resource."""

	message: str


class ForgotPasswordRequest(BaseModel):
	"""Validate an email address submitted for password reset."""

	email: EmailStr


class VerifyEmailRequest(BaseModel):
	"""Validate a token submitted for email verification."""

	token: str = Field(min_length=1)


class ResetPasswordRequest(BaseModel):
	"""Validate a reset token and the new password submitted by the user."""

	token: str = Field(min_length=1)
	new_password: str = Field(min_length=8, max_length=128)

	@field_validator("new_password")
	@classmethod
	def validate_password_strength(cls, value: str) -> str:
		"""Require upper, lower, numeric, and special password characters."""

		requirements = (
			any(c.islower() for c in value),
			any(c.isupper() for c in value),
			any(c.isdigit() for c in value),
			any(not c.isalnum() for c in value),
		)
		if not all(requirements):
			raise ValueError(
				"Password must contain lower, upper, numeric, and special characters"
			)
		return value


class OTPRequest(BaseModel):
	"""Validate an email address submitted to request an OTP."""

	email: EmailStr


class OTPLoginRequest(BaseModel):
	"""Validate the email and OTP code submitted for OTP-based login."""

	email: EmailStr
	otp: str = Field(min_length=6, max_length=6)
