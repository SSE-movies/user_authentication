"""Authentication service API endpoints."""

from flask import Blueprint, request, jsonify, current_app
import bcrypt
import jwt
from datetime import datetime, timedelta
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


@auth_api.route("/api/auth/login", methods=["POST"])
def login():
    """Handle user login and return JWT token."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return (
                jsonify({"error": "Username and password are required"}),
                400,
            )

        # Get user from database
        user_response = (
            supabase.table("profiles")
            .select("*")
            .eq("username", username)
            .execute()
        )

        if not user_response.data:
            return jsonify({"error": "Invalid credentials"}), 401

        user_data = user_response.data[0]

        # Verify password
        if bcrypt.checkpw(
            password.encode("utf-8"), user_data["password"].encode("utf-8")
        ):
            # Generate JWT token
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
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@auth_api.route("/api/auth/register", methods=["POST"])
def register():
    """Handle user registration."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return (
                jsonify({"error": "Username and password are required"}),
                400,
            )

        # Check if username exists
        existing_user = (
            supabase.table("profiles")
            .select("username")
            .eq("username", username)
            .execute()
        )

        if existing_user.data:
            return jsonify({"error": "Username already exists"}), 409

        # Validate password
        password_error = is_valid_password(password)
        if password_error:
            return jsonify({"error": password_error}), 400

        # Hash password and create user
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)

        profile_data = {
            "username": username,
            "password": hashed_password.decode("utf-8"),
            "is_admin": False,
        }

        response = supabase.table("profiles").insert(profile_data).execute()

        if response.data:
            return jsonify({"message": "Registration successful"}), 201
        else:
            return jsonify({"error": "Failed to create user"}), 500

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@auth_api.route("/api/auth/verify", methods=["POST"])
def verify_token():
    """Verify JWT token."""
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
            )
            return jsonify({"valid": True, "user": payload}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    except Exception as e:
        current_app.logger.error(f"Token verification error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
