from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from config import DB_URL


def main():
    engine = create_engine(DB_URL)
    session = Session(bind=engine.connect())

    session.execute('''CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY,
    first_name VARCHAR(256) NOT NULL,
    last_name VARCHAR(256) NOT NULL,
    email VARCHAR(256) NOT NULL,
    password VARCHAR(256) NOT NULL,
    roles VARCHAR(256) NOT NULL);''')

    session.execute('''CREATE TABLE articles (
    id INTEGER NOT NULL PRIMARY KEY,
    authors VARCHAR(256) NOT NULL,
    editors VARCHAR(256) NOT NULL,
    status VARCHAR(256) NOT NULL,
    rating INTEGER NOT NULL,
    readers INTEGER NOT NULL,
    title VARCHAR(256) NOT NULL,
    text TEXT NOT NULL,
    tags VARCHAR(256) NOT NULL,
    created_at VARCHAR(256) NOT NULL,
    section_id INTEGER REFERENCES sections (id) ON DELETE CASCADE);''')

    session.execute('''CREATE TABLE comments (
    id INTEGER NOT NULL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    article_id INTEGER REFERENCES articles (id) ON DELETE CASCADE,
    text TEXT NOT NULL);''')

    session.execute('''CREATE TABLE sections (
    id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    created_by_id INTEGER REFERENCES users (id) ON DELETE CASCADE);''')

    session.execute('''CREATE TABLE auth_tokens (
    id INTEGER NOT NULL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    token VARCHAR(256) NOT NULL,
    created_at VARCHAR(256);''')

    session.close()


if __name__ == '__main__':
    main()
