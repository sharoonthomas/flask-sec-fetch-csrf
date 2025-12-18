"""
Flask application using the factory pattern with CSRF protection.

Run with:
    flask --app examples.factory_pattern:create_app run
"""

from flask import Blueprint, Flask

from flask_sec_fetch_csrf import SecFetchCSRF

csrf = SecFetchCSRF()

api = Blueprint("api", __name__)


@api.route("/data", methods=["POST"])
def post_data():
    return {"status": "ok"}


def create_app(config=None):
    app = Flask(__name__)

    if config:
        app.config.update(config)

    csrf.init_app(app)
    app.register_blueprint(api, url_prefix="/api")

    @app.route("/")
    def index():
        return {"message": "Hello"}

    @app.route("/submit", methods=["POST"])
    def submit():
        return {"status": "submitted"}

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
