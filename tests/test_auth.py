import jwt
import pytest
from datetime import datetime, timedelta, timezone
from flask import Flask
from app.auth import auth_api


@pytest.fixture
def app():
    """Create test Flask application."""
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "test_secret_key"
    app.register_blueprint(auth_api)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


def test_login_missing_credentials(client):
    """Test login with missing credentials."""
    response = client.post("/api/auth/login", json={})
    assert response.status_code == 400
    assert "Username and password are required" in response.get_json()["error"]


def test_register_missing_credentials(client):
    """Test register with missing credentials."""
    response = client.post("/api/auth/register", json={})
    assert response.status_code == 400
    assert "Username and password are required" in response.get_json()["error"]


def test_verify_token_missing_token(client):
    """Test token verification with missing token."""
    response = client.post("/api/auth/verify", json={})
    assert response.status_code == 400
    assert "Token is required" in response.get_json()["error"]


def test_verify_token_expired(client):
    """Test expired token verification."""
    expired_payload = {
        "user_id": 1,
        "username": "test",
        "exp": datetime.now(timezone.utc) - timedelta(days=1),
    }
    expired_token = jwt.encode(
        expired_payload, "test_secret_key", algorithm="HS256"
    )
    response = client.post("/api/auth/verify", json={"token": expired_token})
    assert response.status_code == 401
    assert "expired" in response.get_json()["error"].lower()
