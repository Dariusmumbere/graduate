from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime, date
from passlib.context import CryptContext
from jose import JWTError, jwt
import asyncpg
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")  # Format: postgresql://user:password@host:port/database
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr
    name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True

class GraduateBase(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    date_of_birth: date
    highest_qualification: str
    education_status: str
    employment_status: str
    job_field: Optional[str] = None
    job_title: Optional[str] = None
    company: Optional[str] = None

    @validator('date_of_birth')
    def validate_date_of_birth(cls, v):
        if v > date.today():
            raise ValueError("Date of birth cannot be in the future")
        return v

class GraduateCreate(GraduateBase):
    pass

class Graduate(GraduateBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# Auth setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Graduate Tracking System API",
    description="API for managing graduate data",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection pool
pool = None

async def get_db():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(DATABASE_URL)
    return pool

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

# Auth utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def authenticate_user(db, email: str, password: str):
    user = await db.fetchrow("SELECT * FROM users WHERE email = $1", email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(db=Depends(get_db), token: str = Depends(oauth2_scheme)):
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
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = await db.fetchrow("SELECT id, email, name, is_active FROM users WHERE email = $1", token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Startup event - create tables if they don't exist
@app.on_event("startup")
async def startup():
    db = await get_db()
    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)
    
    await db.execute("""
        CREATE TABLE IF NOT EXISTS graduates (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(50),
            date_of_birth DATE NOT NULL,
            highest_qualification VARCHAR(100) NOT NULL,
            education_status VARCHAR(100) NOT NULL,
            employment_status VARCHAR(100) NOT NULL,
            job_field VARCHAR(100),
            job_title VARCHAR(100),
            company VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            created_by INTEGER REFERENCES users(id)
        )
    """)

# Routes
@app.post("/token", response_model=Token)
async def login_for_access_token(
    db=Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["email"]}
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/register", response_model=User)
async def register_user(user: UserCreate, db=Depends(get_db)):
    # Check if user already exists
    existing_user = await db.fetchrow("SELECT id FROM users WHERE email = $1", user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = await db.fetchrow(
        """
        INSERT INTO users (email, name, password)
        VALUES ($1, $2, $3)
        RETURNING id, email, name, is_active
        """,
        user.email, user.name, hashed_password
    )
    return new_user

@app.get("/auth/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/auth/logout")
async def logout():
    # In a real application, you might want to implement token blacklisting
    return {"message": "Successfully logged out"}

@app.post("/graduates", response_model=Graduate)
async def create_graduate(
    graduate: GraduateCreate,
    db=Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    new_graduate = await db.fetchrow(
        """
        INSERT INTO graduates (
            name, email, phone, date_of_birth, highest_qualification,
            education_status, employment_status, job_field, job_title, company, created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        """,
        graduate.name, graduate.email, graduate.phone, graduate.date_of_birth,
        graduate.highest_qualification, graduate.education_status,
        graduate.employment_status, graduate.job_field, graduate.job_title,
        graduate.company, current_user["id"]
    )
    return new_graduate

@app.get("/graduates", response_model=List[Graduate])
async def read_graduates(
    highest_qualification: Optional[str] = None,
    job_field: Optional[str] = None,
    employment_status: Optional[str] = None,
    db=Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = "SELECT * FROM graduates WHERE 1=1"
    params = []
    
    if highest_qualification:
        query += " AND highest_qualification = $1"
        params.append(highest_qualification)
    
    if job_field:
        query += " AND job_field = $2" if highest_qualification else " AND job_field = $1"
        params.append(job_field)
    
    if employment_status:
        query += " AND employment_status = $3" if highest_qualification and job_field else \
                " AND employment_status = $2" if highest_qualification or job_field else \
                " AND employment_status = $1"
        params.append(employment_status)
    
    query += " ORDER BY created_at DESC"
    
    graduates = await db.fetch(query, *params)
    return graduates

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}
