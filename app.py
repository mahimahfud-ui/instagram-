"""WSGI entry point for the OAuth-first Insight Studio app."""
from oauth_app import app

__all__ = ["app"]

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
