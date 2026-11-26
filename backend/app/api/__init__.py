"""Contract REST API routers."""


def create_app():
    """Compatibility import for callers that historically used ``app.api``."""
    # Import lazily: app.main imports app.api.router while the package loads.
    from app.main import create_app as application_factory

    return application_factory()


__all__ = ["create_app"]
