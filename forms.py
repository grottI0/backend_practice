from pydantic import BaseModel
from typing import Union


class SignInForm(BaseModel):
    email: str
    password: str


class SignUpForm(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    roles: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Union[str, None] = None
    roles: Union[str, None] = None
