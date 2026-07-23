"""Version one routes for registration, login, and token refresh."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.auth import CredentialsRequest, LoginResponse, RegistrationResponse
from app.schemas.token import RefreshTokenRequest
from app.services.auth_service import (
	AuthenticationError,
	authenticate_user,
	create_token_pair,
	register_user,
	rotate_refresh_token,
)


router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
	"/register",
	response_model=RegistrationResponse,
	status_code=status.HTTP_201_CREATED,
)
def register(
	credentials: CredentialsRequest,
	database_session: Session = Depends(get_db),
) -> RegistrationResponse:
	"""Register a new user account with a securely hashed password."""

	try:
		return register_user(database_session, credentials)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_409_CONFLICT,
			detail=str(error),
		) from error


@router.post("/login", response_model=LoginResponse)
def login(
	credentials: CredentialsRequest,
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Authenticate a user and return an access and refresh token pair."""

	try:
		user = authenticate_user(database_session, credentials)
		return create_token_pair(database_session, user)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(error),
			headers={"WWW-Authenticate": "Bearer"},
		) from error


@router.post("/refresh", response_model=LoginResponse)
def refresh(
	request: RefreshTokenRequest,
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Rotate a valid refresh token and revoke the submitted token."""

	try:
		return rotate_refresh_token(database_session, request.refresh_token)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(error),
			headers={"WWW-Authenticate": "Bearer"},
		) from error
