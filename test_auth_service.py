import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import json
import os
from unittest.mock import patch, Mock
from pytest_asyncio import fixture
from datetime import datetime, timedelta, UTC

from auth_service import app, Base, get_db, User, get_password_hash

# Setup test database
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db dependency
@pytest.fixture(scope="function")
def override_get_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        try:
            os.remove("./test_auth.db")
        except:
            pass

@pytest.fixture(scope="function")
def test_client(override_get_db):
    def _get_test_db():
        try:
            yield override_get_db
        finally:
            pass

    app.dependency_overrides[get_db] = _get_test_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def test_user(override_get_db):
    """Create a test user in the database"""
    user = User(
        email="test@example.com",
        hashed_password=get_password_hash("testpassword"),
        is_active=True
    )
    override_get_db.add(user)
    override_get_db.commit()
    return {"email": "test@example.com", "password": "testpassword"}

# Tests for user registration
def test_register_user(test_client):
    """Test successful user registration"""
    response = test_client.post(
        "/register",
        json={"email": "newuser@example.com", "password": "newpassword"}
    )
    assert response.status_code == 201
    assert "User created successfully" in response.json()["message"]

def test_register_duplicate_user(test_client, test_user):
    """Test registration with an existing email"""
    response = test_client.post(
        "/register",
        json={"email": test_user["email"], "password": "newpassword"}
    )
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]

def test_register_with_invalid_data(test_client):
    """Test registration with missing fields"""
    response = test_client.post("/register", json={"email": "newuser@example.com"})
    assert response.status_code == 422  # Pydantic validation error

def test_register_user_invalid_email(test_client):
    """Test user registration with invalid email format"""
    response = test_client.post(
        "/register",
        json={"email": "invalid-email", "password": "testpassword"}
    )
    assert response.status_code == 422  # Validation error

def test_register_user_weak_password(test_client):
    """Test user registration with a weak password"""
    response = test_client.post(
        "/register",
        json={"email": "test@example.com", "password": "123"}  # Too short password
    )
    assert response.status_code == 422

# Tests for login/token endpoint
def test_login_success(test_client, test_user):
    """Test successful login and token generation"""
    response = test_client.post(
        "/token",
        data={"username": test_user["email"], "password": test_user["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(test_client, test_user):
    """Test login with wrong password"""
    response = test_client.post(
        "/token",
        data={"username": test_user["email"], "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_login_nonexistent_user(test_client):
    """Test login with email that doesn't exist"""
    response = test_client.post(
        "/token",
        data={"username": "nonexistent@example.com", "password": "anypassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_login_with_empty_credentials(test_client):
    """Test login attempt with empty credentials"""
    response = test_client.post(
        "/token",
        data={"username": "", "password": ""},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"

# Tests for protected endpoints
def test_get_me_authenticated(test_client, test_user):
    """Test accessing protected endpoint with valid token"""
    # First get token
    login_response = test_client.post(
        "/token",
        data={"username": test_user["email"], "password": test_user["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    token = login_response.json()["access_token"]
    
    # Use token to access protected endpoint
    response = test_client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == test_user["email"]

def test_get_me_unauthorized(test_client):
    """Test accessing protected endpoint without token"""
    response = test_client.get("/users/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]

def test_get_me_invalid_token(test_client):
    """Test accessing protected endpoint with invalid token"""
    response = test_client.get(
        "/users/me",
        headers={"Authorization": "Bearer invalidtoken"}
    )
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]

@pytest.mark.parametrize("malformed_token,expected_message", [
    ("not_a_token", "Not authenticated"),
    ("Bearer without_token", "Could not validate credentials"),
    ("Bearer ", "Could not validate credentials"),
    ("", "Not authenticated"),
])
def test_invalid_token_format(test_client, malformed_token, expected_message):
    """Test various malformed token formats"""
    response = test_client.get(
        "/users/me",
        headers={"Authorization": malformed_token}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == expected_message

def test_missing_authorization_header(test_client):
    """Test accessing protected endpoint without authorization header"""
    response = test_client.get("/users/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

# Test token expiration (requires mocking)
@patch("auth_service.datetime")
def test_token_expiration(mock_datetime, test_client, test_user):
    """Test that an expired token is rejected"""
    from datetime import datetime, timedelta, UTC
    
    # Create a Mock that returns the current_time
    current_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC)
    mock_now = Mock(return_value=current_time)
    mock_datetime.now = mock_now
    mock_datetime.UTC = UTC
    mock_datetime.timedelta = timedelta

    # Get token
    login_response = test_client.post(
        "/token",
        data={"username": test_user["email"], "password": test_user["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Move time forward past token expiration
    future_time = datetime(2023, 1, 1, 12, 16, 0, tzinfo=UTC)  # 16 minutes later
    mock_datetime.now = Mock(return_value=future_time)

    response = test_client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_user_verification_flow(test_client, test_user):
    """Test the complete user verification flow"""
    # Use a unique email to avoid conflicts
    unique_user = {
        "email": f"test_{datetime.now().timestamp()}@example.com",
        "password": "testpassword123"
    }
    
    # Register user
    register_response = test_client.post(
        "/register",
        json=unique_user
    )
    assert register_response.status_code == 201
    
    # Login
    login_response = test_client.post(
        "/token",
        data={"username": unique_user["email"], "password": unique_user["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Get user info
    me_response = test_client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_response.status_code == 200
    user_data = me_response.json()
    assert user_data["email"] == unique_user["email"]

@pytest.fixture(autouse=True)
def setup_database():
    """Setup a fresh database for each test"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine) 