"""Declarative base shared by all SQLAlchemy models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Provide the registry and metadata used by application models."""

    pass
