"""Version one routes for authenticated user resources."""

from fastapi import APIRouter, Depends

from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.user import UserResponse


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
	current_user: User = Depends(get_current_user),
) -> User:
	"""Return the authenticated user's safe public profile."""

	return current_user
