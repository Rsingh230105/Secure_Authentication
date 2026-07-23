"""Declarative base shared by all SQLAlchemy models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Provide the registry and metadata used by application models."""

    pass


# Import models after Base exists so their tables are registered in metadata.
from app.models import otp, token, user  # noqa: E402, F401
