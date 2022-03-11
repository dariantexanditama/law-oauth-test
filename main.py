from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.param_functions import Form
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5


fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "full_name": "Admin Account",
        "npm": "1806205275"
    }
}

fake_session_db = {}


class CustomException(Exception):
    def __init__(self, name: str | None = None):
        self.name = name


class RequestForm:
    def __init__(
        self,
        grant_type: str = Form("password", regex="password"),
        username: str = Form(...),
        password: str = Form(...),
        scope: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret


class Token(BaseModel):
    access_token: str
    expires_in: int
    token_type: str
    scope: str | None = None


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    access_token: str | None = None
    client_id: str | None = None
    username: str
    full_name: str | None = None
    npm: str | None = None
    expires: timedelta | None = None
    refresh_token: str | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI()


@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=401,
        content={
            "error": "invalid_request",
            "error_description": "ada kesalahan masbro!"
        },
        headers={"WWW-Authenticate": "Bearer"}
    )


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise CustomException()
        token_data = TokenData(username=username)
    except JWTError:
        raise CustomException()
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise CustomException()
    return user


@app.post("/oauth/token", response_model=Token)
async def login_for_access_token(form_data: RequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise CustomException()
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token = create_access_token(data={"sub": user.username})
    updates = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires": access_token_expires,
        "client_id": form_data.client_id
    }
    fake_session_db[user.username] = jsonable_encoder(updates)
    return {
        "access_token": access_token,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES*60,
        "token_type": "Bearer",
        "scope": None
    }


@app.post("/oauth/resource/", response_model=User)
async def read_resource_me(current_user: User = Depends(get_current_user)):
    session = fake_session_db[current_user.username]
    return {
        "access_token": session.get("access_token"),
        "client_id": session.get("client_id"),
        "username": current_user.username,
        "full_name": current_user.full_name,
        "npm": current_user.npm,
        "expires": session.get("expires"),
        "refresh_token": session.get("refresh_token")
    }
