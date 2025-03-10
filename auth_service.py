from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime, timedelta, UTC
from azure.data.tables import TableServiceClient
import os
import logging

# -------------------------------
# Logging Setup
# -------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# -------------------------------
# Azure Table Storage Setup
# -------------------------------
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
TABLE_NAME = "Users"

if not AZURE_STORAGE_CONNECTION_STRING:
    logger.error("❌ AZURE_STORAGE_CONNECTION_STRING is not set! Check your environment variables.")
    raise RuntimeError("AZURE_STORAGE_CONNECTION_STRING is required but not set.")

try:
    logger.info("🔍 Connecting to Azure Table Storage...")
    table_service = TableServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    user_table = table_service.get_table_client(TABLE_NAME)
    logger.info("✅ Successfully connected to Azure Table Storage.")

    # Ensure the table exists
    try:
        table_service.create_table(TABLE_NAME)
        logger.info(f"✅ Table '{TABLE_NAME}' created.")
    except Exception:
        logger.info(f"ℹ️ Table '{TABLE_NAME}' already exists.")
except Exception as e:
    logger.error(f"❌ Failed to connect to Azure Table Storage: {str(e)}")
    raise RuntimeError(f"Error initializing Azure Table Storage: {str(e)}")

# -------------------------------
# Authentication Configuration
# -------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # TODO: Change this
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------------------------
# FastAPI App Initialization
# -------------------------------
logger.info("🚀 Starting FastAPI application...")
app = FastAPI()

# Configure CORS (update this in production)
origins = ["*"]  # TODO: Restrict this in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# Models
# -------------------------------
class UserCreate(BaseModel):
    email: str  
    password: str  

    @field_validator("email")
    def validate_email(cls, v):
        if len(v) > 50:
            raise ValueError("Email must be less than 50 characters")
        return v

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return v

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class User:
    def __init__(self, email: str, hashed_password: str, is_active: bool = True, is_verified: bool = False):
        self.PartitionKey = "Users"
        self.RowKey = email
        self.email = email
        self.hashed_password = hashed_password
        self.is_active = is_active
        self.is_verified = is_verified

# -------------------------------
# Utility Functions
# -------------------------------
def get_user(email: str):
    """Retrieve a user from Azure Table Storage by email."""
    try:
        entity = user_table.get_entity(partition_key="Users", row_key=email)
        logger.info(f"🔍 User found: {email}")
        return User(email=entity["email"], hashed_password=entity["hashed_password"],
                    is_active=entity["is_active"], is_verified=entity["is_verified"])
    except Exception as e:
        logger.warning(f"⚠️ User '{email}' not found or error fetching user: {str(e)}")
        return None

def verify_password(plain_password, hashed_password):
    """Verify the password against the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    """Check if user credentials are correct."""
    user = get_user(email)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -------------------------------
# API Endpoints
# -------------------------------
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user and store in Azure Table Storage."""
    logger.info(f"📩 Received registration request for email: {user.email}")

    if get_user(user.email):
        logger.warning(f"⚠️ Registration failed: Email {user.email} already exists.")
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)

    try:
        logger.info(f"📤 Attempting to save user {user.email} to Azure Table Storage.")
        user_table.upsert_entity(vars(new_user))
        logger.info(f"✅ User {user.email} registered successfully.")
        return {"message": "User created successfully"}
    except Exception as e:
        logger.error(f"❌ Error saving user '{user.email}': {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to register user")

@app.get("/debug/connection")
async def debug_connection():
    """API Endpoint to manually test Azure Table Storage connection."""
    try:
        table_service = TableServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
        return {"message": "✅ Successfully connected to Azure Table Storage."}
    except Exception as e:
        return {"error": f"❌ Failed to connect to Azure Table Storage: {str(e)}"}

