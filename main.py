"""FastAPI application entry point for the Secure Authentication API."""

from fastapi import FastAPI

from app.api.v1.auth import router as auth_router
from app.core.config import settings


app = FastAPI(
	title=settings.app_name,
	debug=settings.debug,
)
app.include_router(auth_router, prefix="/api/v1")
