from pydantic import BaseModel


class SignInForm(BaseModel):
    email: str
    password: str


class SignUpForm(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    roles: str
