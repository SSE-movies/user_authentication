from flask import Flask, jsonify
from app.auth import auth_api

app = Flask(__name__)
app.config.from_prefixed_env()

# Register blueprints
app.register_blueprint(auth_api)

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the User Authentication API"})

# This ensures the app is accessible to Gunicorn
application = app

if __name__ == "__main__":
    app.run()
