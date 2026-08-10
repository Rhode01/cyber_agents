"""Outbound HTTP clients.

The ai.engine has no database. Every read or write of platform state goes
through the backend, which is the only module that talks to PostgreSQL.
"""

from ai_engine.clients.backend import BackendClient, BackendError

__all__ = ["BackendClient", "BackendError"]
