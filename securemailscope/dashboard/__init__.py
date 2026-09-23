"""Interactive FastAPI security-monitoring dashboard (optional runtime).

Import lazily via :func:`get_serve` so the package works even when FastAPI /
uvicorn are not installed (the CLI degrades to report generation only).
"""


def get_serve():
    """Return the dashboard ``serve`` callable (imports FastAPI on demand)."""
    from .app import serve
    return serve
