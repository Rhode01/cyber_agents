"""Outbound HTTP clients.

The ai.engine has no database. Every read or write of platform state goes
through the backend, which is the only module that talks to PostgreSQL.
"""

from app.services.backend_client import BackendClient, BackendError

__all__ = ["BackendClient", "BackendError"]
