from pydantic import BaseModel
from typing import Optional


class SignUpVKForm(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str


class SignUpForm(SignUpVKForm):
    admin: Optional[bool] = False


class SignInForm(BaseModel):
    email: str
    password: str


class ChangeRolesForm(BaseModel):
    user_id: int
    roles: str


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
