from fastapi import FastAPI

from database import create_tables
from routes import router


def create_application():
    application = FastAPI()
    application.include_router(router)
    create_tables()
    return application


if __name__ == '__main__':
    app = create_application()
