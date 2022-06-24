from pydantic import BaseModel


class SignInForm(BaseModel):
    login: str
    password: str


class SignUpForm(BaseModel):
    name: str
    email: str
    login: str
    password: str
    roles: str
