import os

from flask import Flask

from .main import register_routes


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-for-graduation-project")
    register_routes(app)
    return app
