"""
pytest fixtures for flask-sec-fetch-csrf tests.
"""
import pytest
from flask import Flask

from flask_sec_fetch_csrf import SecFetchCSRF


@pytest.fixture
def app():
    """Create a Flask test application."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"

    @app.route("/", methods=["GET"])
    def index():
        return "OK"

    @app.route("/submit", methods=["POST"])
    def submit():
        return "OK"

    @app.route("/update", methods=["PUT"])
    def update():
        return "OK"

    @app.route("/delete", methods=["DELETE"])
    def delete():
        return "OK"

    return app


@pytest.fixture
def csrf(app):
    """Initialize CSRF extension on the app."""
    csrf = SecFetchCSRF(app)
    return csrf


@pytest.fixture
def client(app, csrf):
    """Create a test client with CSRF protection enabled."""
    return app.test_client()
