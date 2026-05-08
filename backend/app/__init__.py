from flask import Flask

from .main import register_routes


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    register_routes(app)
    return app

