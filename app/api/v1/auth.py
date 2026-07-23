"""Version one routes for registration, login, and token refresh."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.auth import (
	CredentialsRequest,
	ForgotPasswordRequest,
	LoginResponse,
	MessageResponse,
	RegistrationResponse,
	ResetPasswordRequest,
	VerifyEmailRequest,
)
from app.schemas.token import RefreshTokenRequest
from app.services.auth_service import (
	AuthenticationError,
	authenticate_user,
	create_password_reset_token,
	create_token_pair,
	create_verification_token,
	register_user,
	reset_password,
	rotate_refresh_token,
	verify_email,
)
from app.services.email_service import (
	send_password_reset_email,
	send_verification_email,
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
		user = register_user(database_session, credentials)
		token = create_verification_token(database_session, user)
		try:
			send_verification_email(str(user.email), token)
		except Exception:
			pass  # Never block registration if email delivery fails
		return user
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_409_CONFLICT,
			detail=str(error),
		) from error


@router.post("/login", response_model=LoginResponse)
def login(
	form: OAuth2PasswordRequestForm = Depends(),
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Authenticate a user via OAuth2 form and return an access and refresh token pair."""

	credentials = CredentialsRequest(email=form.username, password=form.password)
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


@router.post(
	"/verify-email",
	response_model=MessageResponse,
	summary="Verify email address",
)
def verify_email_route(
	payload: VerifyEmailRequest,
	database_session: Session = Depends(get_db),
) -> MessageResponse:
	"""Consume a verification token and mark the user's email as verified."""

	try:
		verify_email(database_session, payload.token)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(error),
		) from error
	return MessageResponse(message="Email verified successfully")


@router.post(
	"/forgot-password",
	response_model=MessageResponse,
	summary="Request a password reset email",
)
def forgot_password(
	payload: ForgotPasswordRequest,
	database_session: Session = Depends(get_db),
) -> MessageResponse:
	"""Send a password reset email if the address belongs to an active account.

	Always returns the same response to prevent user enumeration.
	"""

	raw_token = create_password_reset_token(database_session, str(payload.email))
	if raw_token is not None:
		try:
			send_password_reset_email(str(payload.email), raw_token)
		except Exception:
			pass  # Never expose SMTP errors to the caller
	return MessageResponse(message="If that email is registered you will receive a reset link shortly")


@router.post(
	"/reset-password",
	response_model=MessageResponse,
	summary="Reset password using a token",
)
def reset_password_route(
	payload: ResetPasswordRequest,
	database_session: Session = Depends(get_db),
) -> MessageResponse:
	"""Validate a reset token and update the user's password."""

	try:
		reset_password(database_session, payload.token, payload.new_password)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(error),
		) from error
	return MessageResponse(message="Password reset successfully")
