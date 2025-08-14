from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List
from datetime import datetime, date, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import asyncpg
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://graduate_smik_user:7BDuw74Mo5RK1MUFwaTG6BGlbzaz8Wg4@dpg-d2enqguuk2gs73bkgp6g-a/graduate_smik")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@admin.com")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@123")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class UserBase(BaseModel):
    email: EmailStr
    name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool

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

class GraduateCreate(GraduateBase):
    pass

class Graduate(GraduateBase):
    id: int
    created_at: datetime
    updated_at: datetime

class LoginRequest(BaseModel):
    email: str
    password: str

# Auth setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

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

# Auth utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def authenticate_user(db, email: str, password: str):
    user = await db.fetchrow("SELECT * FROM users WHERE email = $1", email)
    if not user or not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(db=Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.fetchrow("SELECT id, email, name, is_active FROM users WHERE email = $1", email)
    if not user:
        raise credentials_exception
    return user

# Startup event - create tables and default admin
@app.on_event("startup")
async def startup():
    db = await get_db()
    
    # Create tables
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
    
    # Create default admin if not exists
    admin_exists = await db.fetchrow("SELECT 1 FROM users WHERE email = $1", DEFAULT_ADMIN_EMAIL)
    if not admin_exists:
        hashed_password = get_password_hash(DEFAULT_ADMIN_PASSWORD)
        await db.execute(
            "INSERT INTO users (email, name, password) VALUES ($1, $2, $3)",
            DEFAULT_ADMIN_EMAIL, "Admin", hashed_password
        )

# Routes
@app.post("/auth/login", response_model=Token)
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db=Depends(get_db)
):
    user = await authenticate_user(db, email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    return {
        "access_token": create_access_token({"sub": user["email"]}),
        "token_type": "bearer"
    }
    
@app.post("/token", response_model=Token)
async def login(
    db=Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    return {
        "access_token": create_access_token({"sub": user["email"]}),
        "token_type": "bearer"
    }

@app.post("/auth/register", response_model=User)
async def register(user: UserCreate, db=Depends(get_db)):
    existing_user = await db.fetchrow("SELECT id FROM users WHERE email = $1", user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = await db.fetchrow(
        "INSERT INTO users (email, name, password) VALUES ($1, $2, $3) RETURNING id, email, name, is_active",
        user.email, user.name, hashed_password
    )
    return new_user

@app.get("/auth/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

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
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, name, email, phone, date_of_birth, highest_qualification,
                  education_status, employment_status, job_field, job_title, company,
                  created_at, updated_at
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
    param_count = 1
    
    if highest_qualification:
        query += f" AND highest_qualification = ${param_count}"
        params.append(highest_qualification)
        param_count += 1
    
    if job_field:
        query += f" AND job_field = ${param_count}"
        params.append(job_field)
        param_count += 1
    
    if employment_status:
        query += f" AND employment_status = ${param_count}"
        params.append(employment_status)
    
    query += " ORDER BY created_at DESC"
    return await db.fetch(query, *params)

    
# Health check
@app.get("/health")
async def health_check():
    return {"status": "ok"}
