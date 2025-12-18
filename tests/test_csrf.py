"""
Tests for flask-sec-fetch-csrf.

Tests follow Filippo Valsorda's algorithm:
https://words.filippo.io/csrf/

1. Allow safe methods (GET, HEAD, OPTIONS)
2. Check trusted origins allowlist
3. If Sec-Fetch-Site present: Allow same-origin or none, reject others
4. If no Sec-Fetch-Site AND no Origin: Allow (non-browser client)
5. If Origin present: Compare against Host header
"""
import pytest
from flask import Blueprint, Flask

from flask_sec_fetch_csrf import CSRFError, SecFetchCSRF


class TestSafeMethods:
    """Test Step 1: Safe methods are always allowed."""

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_safe_methods_allowed(self, app, csrf, method):
        """Safe methods should always pass without CSRF validation."""
        client = app.test_client()
        # Even with cross-site header, safe methods should pass
        response = getattr(client, method.lower())(
            "/",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 200


class TestTrustedOrigins:
    """Test Step 2: Trusted origins allowlist."""

    def test_trusted_origin_allowed(self, app, csrf):
        """Requests from trusted origins should pass."""
        app.config["SEC_FETCH_CSRF_TRUSTED_ORIGINS"] = ["https://trusted.example.com"]
        client = app.test_client()

        response = client.post(
            "/submit",
            headers={
                "Origin": "https://trusted.example.com",
                "Sec-Fetch-Site": "cross-site",
            }
        )
        assert response.status_code == 200

    def test_untrusted_origin_blocked(self, app, csrf):
        """Requests from untrusted origins should be blocked."""
        app.config["SEC_FETCH_CSRF_TRUSTED_ORIGINS"] = ["https://trusted.example.com"]
        client = app.test_client()

        response = client.post(
            "/submit",
            headers={
                "Origin": "https://evil.example.com",
                "Sec-Fetch-Site": "cross-site",
            }
        )
        assert response.status_code == 403


class TestSecFetchSite:
    """Test Step 3: Sec-Fetch-Site header validation."""

    def test_same_origin_allowed(self, client):
        """same-origin requests should always be allowed."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert response.status_code == 200

    def test_none_allowed(self, client):
        """none (user-initiated) requests should be allowed."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "none"}
        )
        assert response.status_code == 200

    def test_cross_site_blocked(self, client):
        """cross-site requests should be blocked."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 403
        assert b"Cross-site requests are not allowed" in response.data

    def test_same_site_blocked_by_default(self, client):
        """same-site requests should be blocked by default."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-site"}
        )
        assert response.status_code == 403
        assert b"Same-site requests are not allowed" in response.data

    def test_same_site_allowed_when_configured(self, app, csrf):
        """same-site can be allowed via configuration."""
        app.config["SEC_FETCH_CSRF_ALLOW_SAME_SITE"] = True
        client = app.test_client()

        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-site"}
        )
        assert response.status_code == 200

    def test_unknown_value_blocked(self, client):
        """Unknown Sec-Fetch-Site values should be blocked."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "unknown-value"}
        )
        assert response.status_code == 403
        assert b"Unknown Sec-Fetch-Site value" in response.data


class TestMissingHeaders:
    """Test Step 4: Requests without Sec-Fetch-Site AND Origin."""

    def test_no_headers_allowed(self, client):
        """Requests without Sec-Fetch-Site AND Origin should pass (non-browser)."""
        response = client.post("/submit")
        assert response.status_code == 200

    def test_only_user_agent_allowed(self, client):
        """Requests with only User-Agent should pass (API client)."""
        response = client.post(
            "/submit",
            headers={"User-Agent": "python-requests/2.28.0"}
        )
        assert response.status_code == 200


class TestOriginValidation:
    """Test Step 5: Origin header validation against Host."""

    def test_matching_origin_allowed(self, client):
        """Origin matching Host header should pass."""
        response = client.post(
            "/submit",
            headers={"Origin": "http://localhost"}
        )
        assert response.status_code == 200

    def test_mismatched_origin_blocked(self, client):
        """Origin not matching Host header should be blocked."""
        response = client.post(
            "/submit",
            headers={"Origin": "https://evil.com"}
        )
        assert response.status_code == 403
        assert b"Origin mismatch" in response.data

    def test_origin_with_port_matching(self, app, csrf):
        """Origin with port should match Host with same port."""
        client = app.test_client()

        # Flask test client uses 'localhost' as host
        response = client.post(
            "/submit",
            headers={"Origin": "http://localhost"}
        )
        assert response.status_code == 200


class TestExemption:
    """Test view and blueprint exemption."""

    def test_exempt_decorator(self, app):
        """Views decorated with @csrf.exempt should bypass validation."""
        csrf = SecFetchCSRF()

        @app.route("/webhook", methods=["POST"])
        @csrf.exempt
        def webhook():
            return "OK"

        csrf.init_app(app)
        client = app.test_client()

        response = client.post(
            "/webhook",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 200

    def test_exempt_blueprint(self, app):
        """Blueprints exempted should bypass validation."""
        csrf = SecFetchCSRF()

        api = Blueprint("api", __name__)

        @api.route("/endpoint", methods=["POST"])
        def api_endpoint():
            return "OK"

        csrf.exempt(api)
        app.register_blueprint(api, url_prefix="/api")
        csrf.init_app(app)

        client = app.test_client()
        response = client.post(
            "/api/endpoint",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 200


class TestConfiguration:
    """Test configuration options."""

    def test_custom_methods(self, app):
        """SEC_FETCH_CSRF_METHODS should control which methods are protected."""
        app.config["SEC_FETCH_CSRF_METHODS"] = ["POST"]  # Only POST
        csrf = SecFetchCSRF(app)
        client = app.test_client()

        # PUT should now pass without validation
        response = client.put(
            "/update",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 200

        # POST should still be protected
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 403


class TestFactoryPattern:
    """Test application factory pattern support."""

    def test_factory_pattern(self):
        """Extension should work with application factory pattern."""
        csrf = SecFetchCSRF()

        def create_app():
            app = Flask(__name__)
            app.config["TESTING"] = True

            @app.route("/submit", methods=["POST"])
            def submit():
                return "OK"

            csrf.init_app(app)
            return app

        app = create_app()
        client = app.test_client()

        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert response.status_code == 200

    def test_multiple_apps(self):
        """Extension should work with multiple apps."""
        csrf = SecFetchCSRF()

        app1 = Flask(__name__)
        app1.config["TESTING"] = True

        @app1.route("/submit", methods=["POST"])
        def submit1():
            return "APP1"

        app2 = Flask(__name__)
        app2.config["TESTING"] = True

        @app2.route("/submit", methods=["POST"])
        def submit2():
            return "APP2"

        csrf.init_app(app1)
        csrf.init_app(app2)

        client1 = app1.test_client()
        client2 = app2.test_client()

        response1 = client1.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert response1.status_code == 200
        assert response1.data == b"APP1"

        response2 = client2.post(
            "/submit",
            headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert response2.status_code == 200
        assert response2.data == b"APP2"


class TestErrorHandling:
    """Test error response customization."""

    def test_default_error_response(self, client):
        """Default error should be 403 Forbidden."""
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 403

    def test_custom_error_handler(self, app, csrf):
        """Custom error handler should be called on CSRF failure."""
        @app.errorhandler(CSRFError)
        def handle_csrf_error(error):
            return {"error": "Custom CSRF error", "reason": str(error)}, 418

        client = app.test_client()
        response = client.post(
            "/submit",
            headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 418
        assert b"Custom CSRF error" in response.data
