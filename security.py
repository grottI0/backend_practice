from datetime import datetime, timedelta
from typing import Union
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from config import ALGORITHM, KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from database import connection, User
from main import oauth2_scheme
from forms import TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(email: str, db=Depends(connection)):
    current_user = db.query(User).filter(User.email == email)
    if current_user:
        return current_user


def authenticate_user(db, email: str, password: str):
    user = get_user(email, db)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                              detail='Could not validate credentials',
                              headers={'WWW-Authenticate': 'Bearer'})
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        email: str = payload['email']
        roles: str = payload['roles']
        if email is None or roles is None:
            raise exception
        token_data = TokenData(email=email, roles=roles)
    except JWTError:
        raise exception
    user = get_user(email=token_data.email)
    if user is None:
        raise exception

    return user



