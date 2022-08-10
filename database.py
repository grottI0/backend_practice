import os

from sqlalchemy import create_engine, MetaData, Column, Integer, String, ForeignKey, Text, BOOLEAN
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base

metadata = MetaData()
Base = declarative_base()


def db_url():
    url = os.environ['DATABASE_URL'].split('://')
    url[0] = url[0] + 'ql+psycopg2://'
    url = ''.join(url)
    return url


DB_URL = db_url()
engine = create_engine(DB_URL)


def connection():
    session = Session(bind=engine.connect())
    return session


def create_tables():
    Base.metadata.create_all(engine)


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    roles = Column(String)
    blocked = Column(BOOLEAN, default=False)
    vk_id = Column(String, unique=True)


class Article(Base):
    __tablename__ = 'articles'
    id = Column(Integer, primary_key=True)
    creator = Column(String, nullable=False)
    authors = Column(String, nullable=False)
    editors = Column(String)
    status = Column(String, nullable=False)
    rating = Column(Integer)
    readers = Column(Integer)
    title = Column(String, nullable=False, unique=True)
    text = Column(Text, nullable=False)
    tags = Column(String, nullable=False)
    approved_at = Column(String)
    section_id = Column(Integer, ForeignKey('sections.id'))
    number_of_ratings = Column(Integer)


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    text = Column(String, nullable=False)


class Section(Base):
    __tablename__ = 'sections'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    creator_id = Column(Integer, ForeignKey('users.id'))


class Rating(Base):
    __tablename__ = 'ratings'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    rating = Column(Integer, nullable=False)


class SessionTable(Base):
    __tablename__ = 'sessions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    session_id = Column(String, nullable=False, unique=True)
