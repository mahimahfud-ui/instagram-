# Compatibility entry point for deployments configured as app:app.
# The actual app is a safe, informational demo and does not collect credentials.
from app_updated import app

__all__ = ["app"]
