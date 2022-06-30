from pydantic import BaseModel
from typing import Union


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
    id: int
    email: Union[str, None] = None
    roles: str
    full_name: Union[str, None] = None


class DraftCreateForm(BaseModel):
    title: str
    text: str
    tags: str
    other_authors: str


class DraftEditForm(BaseModel):
    text: str
    tags: str


class CommentForm(BaseModel):
    text: str
    rating: int
