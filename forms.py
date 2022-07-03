from pydantic import BaseModel


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
    full_name: str
    blocked: bool


class DraftCreateForm(BaseModel):
    title: str
    text: str
    tags: str
    other_authors: str  # ids str -> '1 3'


class DraftEditForm(BaseModel):
    text: str
    tags: str


class ApprovedEditForm(BaseModel):
    edited_text: str
    other_editors: str  # ids str
