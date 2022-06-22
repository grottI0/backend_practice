from fastapi import FastAPI
from pydantic import BaseModel


class User(BaseModel):
    name: str
    login: str
    password: str


app = FastAPI()


@app.post('/reg')
def registration(body: User):
    return body

