"""The ai.engine: a standalone LangGraph service.

Every detection agent is a LangGraph graph behind its own FastAPI router. This
service holds no database. When it needs to read or write platform state it
calls the backend over HTTP.
"""

__version__ = "0.1.0"
