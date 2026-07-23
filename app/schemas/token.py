"""Request and response schemas for refresh-token rotation."""

from pydantic import BaseModel, Field


class RefreshTokenRequest(BaseModel):
	"""Validate a refresh token submitted for rotation."""

	refresh_token: str = Field(min_length=1)
