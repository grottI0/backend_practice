from pydantic import BaseModel
from typing import Union


class SignUpForm(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Union[str, None] = None
    roles: str
    full_name: Union[str, None] = None


class DraftForm(BaseModel):
    title: str
    text: str
    tags: str
    authors: str


class PublishedForm(DraftForm):
    created_at: Union[str, None] = None
    authors: Union[str, None]  # full names
    editors: Union[str, None] = None  # full names


class ApprovedForm(PublishedForm):
    rating: Union[int, None] = None
    readers: Union[int, None] = None


class RejectedForm(PublishedForm):
    message: str
