from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from config import DB_URL


def main():
    engine = create_engine(DB_URL)
    print(engine)

    session = Session(bind=engine.connect())
    print(session)

    session.execute('''CREATE TABLE users (
    id SERIAL NOT NULL PRIMARY KEY,
    full_name VARCHAR(256) NOT NULL,
    email VARCHAR(256) NOT NULL UNIQUE,
    password VARCHAR(256) NOT NULL,
    roles VARCHAR(256) NOT NULL),
    blocked BOOLEAN DEFAULT false;''')

    session.execute('''CREATE TABLE sections (
    id SERIAL NOT NULL PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    created_by_id INTEGER REFERENCES users (id) ON DELETE CASCADE);''')

    session.execute('''CREATE TABLE articles (
    id SERIAL NOT NULL PRIMARY KEY,
    creator VARCHAR(256) NOT NULL,
    authors VARCHAR(256) NOT NULL,
    editors VARCHAR(256),
    status VARCHAR(256) NOT NULL,
    rating INTEGER,
    number_of_ratings INTEGER,
    readers INTEGER,
    title VARCHAR(256) NOT NULL UNIQUE,
    text TEXT NOT NULL,
    tags VARCHAR(256) NOT NULL,
    created_at VARCHAR(256) NOT NULL,
    section_id INTEGER REFERENCES sections (id) ON DELETE CASCADE);''')

    session.execute('''CREATE TABLE comments (
    id SERIAL NOT NULL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    article_id INTEGER REFERENCES articles (id) ON DELETE CASCADE,
    text TEXT NOT NULL);''')

    session.execute('''CREATE TABLE ratings (
    id SERIAL NOT NULL PRIMARY KEY,
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    article_id INTEGER REFERENCES articles (id) ON DELETE CASCADE,
    rating INTEGER NOT NULL);''')

    session.commit()
    session.close()


if __name__ == '__main__':
    main()
