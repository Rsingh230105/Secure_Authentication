"""Reusable FastAPI dependencies for authenticated requests."""

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.database.database import get_db
from app.models.user import User


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
	token: str = Depends(oauth2_scheme),
	database_session: Session = Depends(get_db),
) -> User:
	"""Validate an access token and return its active database user."""

	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate authentication credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)

	try:
		claims = decode_token(token)
		subject = claims.get("sub")
		if claims.get("type") != "access" or not subject:
			raise credentials_exception
		user_id = UUID(subject)
	except (JWTError, TypeError, ValueError) as error:
		raise credentials_exception from error

	user = database_session.get(User, user_id)
	if user is None or not user.is_active:
		raise credentials_exception
	return user
