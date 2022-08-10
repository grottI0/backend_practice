from fastapi import FastAPI

from database import create_tables
from routes import router


def create_application():
    application = FastAPI()
    application.include_router(router)
    create_tables()
    return application


app = create_application()
