from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime, timedelta, UTC
from azure.data.tables import TableServiceClient, TableClient
import os

# -------------------------------
# Azure Table Storage Setup
# -------------------------------
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
TABLE_NAME = "Users"

table_service = TableServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
user_table = table_service.get_table_client(TABLE_NAME)

# Ensure table exists
try:
    table_service.create_table(TABLE_NAME)
except Exception:
    pass

# -------------------------------
# Authentication Configuration
# -------------------------------
SECRET_KEY = "your-secret-key"  # TODO: Change this to a secure value
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------------------------
# FastAPI App Initialization
# -------------------------------
app = FastAPI()

# Configure CORS (update this in production)
origins = ["*"] # TODO CHANGE THIS!
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
        if len(v) > 20:  # Adjust email length limit
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
        return User(email=entity["email"], hashed_password=entity["hashed_password"],
                    is_active=entity["is_active"], is_verified=entity["is_verified"])
    except:
        return None  # User not found

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
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)

    # Insert into Azure Table Storage
    user_table.upsert_entity(vars(new_user))

    return {"message": "User created successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return a JWT token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.email}

async def get_current_user(
    token: str = Depends(oauth2_scheme),
):
    """Validate JWT token and retrieve user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(email)
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Return the currently logged-in user's information."""
    return current_user
