"""Authentication service API endpoints."""
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional, Callable
from dataclasses import dataclass

import bcrypt
import jwt
from flask import Blueprint, current_app, jsonify, request, Response
from supabase import Client

from .database import supabase
from .utils import is_valid_password

auth_api = Blueprint("auth_api", __name__)

@dataclass
class AuthResponse:
    """Data class for authentication responses."""
    response: Response
    status_code: int

def create_token(user_data: Dict[str, Any]) -> str:
    """Create a JWT token for the user."""
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "is_admin": user_data.get("is_admin", False),
        "exp": datetime.utcnow() + timedelta(days=1),
    }
    return jwt.encode(
        payload, 
        current_app.config['JWT_SECRET_KEY'], 
        algorithm='HS256'
    )

def validate_request_data(data: Optional[Dict[str, Any]]) -> Optional[AuthResponse]:
    """Validate request data for login and registration."""
    if not data:
        return AuthResponse(jsonify({"error": "Invalid request data"}), 400)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return AuthResponse(
            jsonify({"error": "Username and password are required"}), 
            400
        )
    return None

def handle_database_operation(
    operation: str, 
    func: Callable[[], Any]
) -> Tuple[Any, Optional[AuthResponse]]:
    """Handle database operations with proper error handling."""
    try:
        return func(), None
    except (ValueError, Client.ApiError) as e:
        current_app.logger.error(f"Database error during {operation}: {str(e)}")
        return None, AuthResponse(
            jsonify({"error": "Database operation failed"}), 
            500
        )

def handle_login_response(user_data: Dict[str, Any]) -> AuthResponse:
    """Handle successful login response."""
    try:
        token = create_token(user_data)
        return AuthResponse(jsonify({
            "token": token,
            "user": {
                "id": user_data["id"],
                "username": user_data["username"],
                "is_admin": user_data.get("is_admin", False)
            }
        }), 200)
    except jwt.PyJWTError as e:
        current_app.logger.error(f"Token generation error: {str(e)}")
        return AuthResponse(
            jsonify({"error": "Token generation failed"}), 
            500
        )

def handle_auth_error(error: Exception, operation: str) -> AuthResponse:
    """Centralized error handling for authentication operations."""
    if isinstance(error, jwt.InvalidTokenError):
        current_app.logger.error(f"JWT error in {operation}: {str(error)}")
        return AuthResponse(
            jsonify({"error": "Authentication failed"}), 
            401
        )
    if isinstance(error, ValueError):
        current_app.logger.error(f"Value error in {operation}: {str(error)}")
        return AuthResponse(jsonify({"error": str(error)}), 400)
    current_app.logger.error(f"Unexpected error in {operation}: {str(error)}")
    return AuthResponse(
        jsonify({"error": "Internal server error"}), 
        500
    )

@auth_api.route("/api/auth/login", methods=["POST"])
def login() -> Tuple[Response, int]:
    """Handle user login and return JWT token."""
    try:
        validation_result = validate_request_data(request.get_json())
        if validation_result:
            return validation_result.response, validation_result.status_code

        data = request.get_json()
        username = data["username"]
        password = data["password"]

        user_response, error = handle_database_operation(
            "user lookup",
            lambda: supabase.table("profiles")
            .select("*")
            .eq("username", username)
            .execute()
        )
        if error:
            return error.response, error.status_code

        if not user_response.data:
            return jsonify({"error": "Invalid credentials"}), 401

        user_data = user_response.data[0]

        try:
            if not bcrypt.checkpw(
                password.encode("utf-8"),
                user_data["password"].encode("utf-8")
            ):
                return jsonify({"error": "Invalid credentials"}), 401
        except ValueError as e:
            current_app.logger.error(f"Password verification error: {str(e)}")
            return jsonify({"error": "Password verification failed"}), 401

        result = handle_login_response(user_data)
        return result.response, result.status_code

    except Exception as e:
        error_response = handle_auth_error(e, "login")
        return error_response.response, error_response.status_code

@auth_api.route("/api/auth/register", methods=["POST"])
def register() -> Tuple[Response, int]:
    """Handle user registration."""
    try:
        validation_result = validate_request_data(request.get_json())
        if validation_result:
            return validation_result.response, validation_result.status_code

        data = request.get_json()
        username = data["username"]
        password = data["password"]

        existing_user, error = handle_database_operation(
            "user existence check",
            lambda: supabase.table("profiles")
            .select("username")
            .eq("username", username)
            .execute()
        )
        if error:
            return error.response, error.status_code

        if existing_user.data:
            return jsonify({"error": "Username already exists"}), 409

        password_error = is_valid_password(password)
        if password_error:
            return jsonify({"error": password_error}), 400

        try:
            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), 
                bcrypt.gensalt()
            )
            profile_data = {
                "username": username,
                "password": hashed_password.decode("utf-8"),
                "is_admin": False,
            }

            response, error = handle_database_operation(
                "user creation",
                lambda: supabase.table("profiles").insert(profile_data).execute()
            )
            if error:
                return error.response, error.status_code

            if not response.data:
                return jsonify({"error": "Failed to create user"}), 500

            return jsonify({"message": "Registration successful"}), 201

        except Exception as e:
            error_response = handle_auth_error(e, "registration")
            return error_response.response, error_response.status_code

    except Exception as e:
        error_response = handle_auth_error(e, "registration")
        return error_response.response, error_response.status_code

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
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            return jsonify({"valid": True, "user": payload}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    except Exception as e:
        current_app.logger.error(f"Token verification error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
