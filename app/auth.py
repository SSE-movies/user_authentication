"""Authentication service API endpoints."""

from datetime import datetime, timedelta
import bcrypt
import jwt
from flask import Blueprint, request, jsonify, current_app
from postgrest.exceptions import APIError
from .database import supabase
from .utils import is_valid_password

auth_api = Blueprint("auth_api", __name__)


def create_token(user_data: dict) -> str:
    """Create a JWT token for the user."""
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "is_admin": user_data.get("is_admin", False),
        "exp": datetime.utcnow() + timedelta(days=1),
    }
    return jwt.encode(
        payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )


def validate_login_data(data):
    """Validate login request data."""
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return None, (
            jsonify({"error": "Username and password are required"}),
            400,
        )
    return (username, password), None


@auth_api.route("/api/auth/login", methods=["POST"])
def login():
    """Handle user login and return JWT token."""
    try:
        data = request.get_json()
        credentials, error = validate_login_data(data)
        if error:
            return error

        username, password = credentials
        user_response = (
            supabase.table("profiles")
            .select("*")
            .eq("username", username)
            .execute()
        )

        if not user_response.data:
            return jsonify({"error": "Invalid credentials"}), 401

        user_data = user_response.data[0]
        if not bcrypt.checkpw(
            password.encode("utf-8"), user_data["password"].encode("utf-8")
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_token(user_data)
        return jsonify(
            {
                "token": token,
                "user": {
                    "id": user_data["id"],
                    "username": user_data["username"],
                    "is_admin": user_data.get("is_admin", False),
                },
            }
        )

    except (jwt.InvalidTokenError, ValueError) as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 401
    except APIError as e:
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": "Database error"}), 500


def create_user_profile(username: str, password: str) -> tuple:
    """Create a new user profile."""
    try:
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        )
        profile_data = {
            "username": username,
            "password": hashed_password.decode("utf-8"),
            "is_admin": False,
        }
        response = supabase.table("profiles").insert(profile_data).execute()
        if not response.data:
            return None, (jsonify({"error": "Failed to create user"}), 500)
        return response.data, None
    except (ValueError, UnicodeEncodeError) as e:
        return None, (
            jsonify({"error": f"Password encoding error: {str(e)}"}),
            400,
        )
    except APIError as e:
        return None, (jsonify({"error": f"Database error: {str(e)}"}), 500)


@auth_api.route("/api/auth/register", methods=["POST"])
def register():
    """Handle user registration."""

    def validate_input(data):
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return None, (
                jsonify({"error": "Username and password are required"}),
                400,
            )
        return (username, password), None

    try:
        data = request.get_json()
        credentials, error = validate_input(data)
        if error:
            return error

        username, password = credentials
        existing_user = (
            supabase.table("profiles")
            .select("username")
            .eq("username", username)
            .execute()
        )

        if existing_user.data:
            return jsonify({"error": "Username already exists"}), 409

        password_error = is_valid_password(password)
        if password_error:
            return jsonify({"error": password_error}), 400

        _, error = create_user_profile(username, password)
        if error:
            return error

        return jsonify({"message": "Registration successful"}), 201

    except APIError as e:
        current_app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": "Database error"}), 500


@auth_api.route("/api/auth/verify", methods=["POST"])
def verify_token():
    """Verify JWT token."""
    try:
        data = request.get_json()
        token = data.get("token")
        if not token:
            return jsonify({"error": "Token is required"}), 400

        decoded = jwt.decode(
            token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"]
        )
        return jsonify({"valid": True, "user": decoded})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401
    except (TypeError, KeyError) as e:  # More specific than ValueError
        return jsonify({"error": f"Token validation error: {str(e)}"}), 400
