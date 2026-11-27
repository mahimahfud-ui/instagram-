"""Kept for compatibility — same as app.py."""
from oauth_app import app

__all__ = ["app"]

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            debug=False, threaded=True)
