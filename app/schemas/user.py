"""Public user response schemas."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr


class UserResponse(BaseModel):
	"""Expose safe user fields without returning password material."""

	model_config = ConfigDict(from_attributes=True)

	id: UUID
	email: EmailStr
	is_active: bool
	is_verified: bool
