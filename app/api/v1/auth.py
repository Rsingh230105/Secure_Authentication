"""Version one routes for registration, login, and token refresh."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.schemas.auth import (
	CredentialsRequest,
	ForgotPasswordRequest,
	LoginResponse,
	MessageResponse,
	OTPLoginRequest,
	OTPRequest,
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
	send_otp_email,
	send_password_reset_email,
	send_verification_email,
)
from app.services.otp_service import request_otp, verify_otp_and_login
from app.services.oauth_service import (
	google_authorization_url,
	handle_google_callback,
	github_authorization_url,
	handle_github_callback,
)


router = APIRouter(prefix="/auth", tags=["authentication"])


# ---------------------------------------------------------------------------
# Google OAuth2
# ---------------------------------------------------------------------------


@router.get("/google", summary="Initiate Google OAuth2 login")
def google_login() -> RedirectResponse:
	"""Redirect the browser to Google's OAuth2 consent screen."""

	try:
		url = google_authorization_url()
	except Exception as error:
		raise HTTPException(
			status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
			detail=str(error),
		) from error
	return RedirectResponse(url=url)


@router.get(
	"/google/callback",
	response_model=LoginResponse,
	summary="Google OAuth2 callback",
)
def google_callback(
	code: str = Query(..., description="Authorization code returned by Google"),
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Exchange a Google authorization code for a JWT access and refresh token pair."""

	try:
		return handle_google_callback(database_session, code)
	except Exception as error:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(error),
			headers={"WWW-Authenticate": "Bearer"},
		) from error


# ---------------------------------------------------------------------------
# GitHub OAuth2
# ---------------------------------------------------------------------------


@router.get("/github", summary="Initiate GitHub OAuth2 login")
def github_login() -> RedirectResponse:
	"""Redirect the browser to GitHub's OAuth2 authorization screen."""

	try:
		url = github_authorization_url()
	except Exception as error:
		raise HTTPException(
			status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
			detail=str(error),
		) from error
	return RedirectResponse(url=url)


@router.get(
	"/github/callback",
	response_model=LoginResponse,
	summary="GitHub OAuth2 callback",
)
def github_callback(
	code: str = Query(..., description="Authorization code returned by GitHub"),
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Exchange a GitHub authorization code for a JWT access and refresh token pair."""

	try:
		return handle_github_callback(database_session, code)
	except Exception as error:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(error),
			headers={"WWW-Authenticate": "Bearer"},
		) from error


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


@router.post(
	"/request-otp",
	response_model=MessageResponse,
	summary="Request a one-time password for OTP login",
)
def request_otp_route(
	payload: OTPRequest,
	database_session: Session = Depends(get_db),
) -> MessageResponse:
	"""Generate an OTP for the given email and deliver it via email.

	During development, when SMTP is not configured, the raw OTP is printed
	to the terminal so it can be used for testing.
	"""

	try:
		raw_otp = request_otp(database_session, str(payload.email))
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(error),
		) from error

	if settings.smtp_host:
		try:
			send_otp_email(str(payload.email), raw_otp, settings.otp_expire_minutes)
		except Exception:
			pass  # Never expose SMTP errors to the caller
	else:
		# DEV ONLY — remove before production
		print(f"[DEV] OTP for {payload.email}: {raw_otp}")

	return MessageResponse(message="If that email is registered you will receive a one-time password shortly")


@router.post(
	"/login-otp",
	response_model=LoginResponse,
	summary="Login using a one-time password",
)
def login_otp(
	payload: OTPLoginRequest,
	database_session: Session = Depends(get_db),
) -> LoginResponse:
	"""Verify a submitted OTP and return a JWT access and refresh token pair."""

	try:
		return verify_otp_and_login(database_session, str(payload.email), payload.otp)
	except AuthenticationError as error:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(error),
			headers={"WWW-Authenticate": "Bearer"},
		) from error
