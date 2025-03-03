from flask import Flask
from app.auth import auth_api

app = Flask(__name__)
app.config.from_prefixed_env()

# Register blueprints
app.register_blueprint(auth_api)

if __name__ == "__main__":
    app.run()
