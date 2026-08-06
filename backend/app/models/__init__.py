"""SQLAlchemy models.

Alembic imports this package so every table registers on ``Base.metadata``.
Any new model must be re-exported here or autogenerate will not see it.
"""

from app.models.finding import Finding
from app.models.run import Run
from app.models.scan import Scan

__all__ = ["Finding", "Run", "Scan"]
