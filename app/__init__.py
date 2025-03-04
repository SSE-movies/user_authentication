from flask import Flask, jsonify
from app.auth import auth_api


def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env()

    # Register blueprints
    app.register_blueprint(auth_api)

    @app.route("/")
    def home():
        return jsonify({"message": "Welcome to the User Authentication API"})

    return app


# Create the application instance
app = create_app()
