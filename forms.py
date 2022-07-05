from pydantic import BaseModel
from typing import Optional


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
    roles: str
    blocked: bool


class DraftCreateForm(BaseModel):
    title: str
    text: str
    tags: str
    other_authors: Optional[str]  # ids str -> '1 3'


class DraftEditForm(BaseModel):
    title: str
    text: str
    tags: str


class ApprovedEditForm(BaseModel):
    title: str
    edited_text: Optional[str]
    other_editors: Optional[str]  # ids str


class RejectForm(BaseModel):
    title: str
    message: str
