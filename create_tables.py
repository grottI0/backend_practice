from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import ProgrammingError

from database import DB_URL


# функция создания таблиц базы данных
def create_tables():
    engine = create_engine(DB_URL)
    try:
        session = Session(bind=engine.connect())
        session.execute('''CREATE TABLE users (
        id SERIAL NOT NULL PRIMARY KEY,
        full_name VARCHAR(256) NOT NULL,
        email VARCHAR(256) NOT NULL UNIQUE,
        password VARCHAR(256) NOT NULL,
        roles VARCHAR(256) NOT NULL,
        blocked BOOLEAN DEFAULT false),
        vk_id VARCHAR(256) UNIQUE;''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('users already exists')

    try:
        session = Session(bind=engine.connect())
        session.execute('''CREATE TABLE sections (
        id SERIAL NOT NULL PRIMARY KEY,
        name VARCHAR(256) NOT NULL,
        created_by_id INTEGER REFERENCES users (id) ON DELETE CASCADE);''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('sections already exists')

    try:
        session = Session(bind=engine.connect())
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
        approved_at VARCHAR(256),
        section_id INTEGER REFERENCES sections (id) ON DELETE CASCADE);''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('articles already exists')

    try:
        session = Session(bind=engine.connect())
        session.execute('''CREATE TABLE comments (
        id SERIAL NOT NULL PRIMARY KEY,
        user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
        article_id INTEGER REFERENCES articles (id) ON DELETE CASCADE,
        text TEXT NOT NULL);''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('comments already exists')

    try:
        session = Session(bind=engine.connect())
        session.execute('''CREATE TABLE ratings (
        id SERIAL NOT NULL PRIMARY KEY,
        user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
        article_id INTEGER REFERENCES articles (id) ON DELETE CASCADE,
        rating INTEGER NOT NULL);''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('rating already exists')

    try:
        session = Session(bind=engine.connect())
        session.execute('''CREATE TABLE sessions (
        id SERIAL NOT NULL PRIMARY KEY,
        user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
        session_id VARCHAR(256) NOT NULL UNIQUE);''')
        session.commit()
        session.close()
    except ProgrammingError:
        print('sessions already exists')
