from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import Session
from sqlalchemy.exc.declarative import declarative_base
from datetime import datetime

from config import DB_URL


Base = declarative_base()


def connection():
    engine = create_engine(DB_URL)  # connect_args={})
    session = Session(bind=engine.connect())
    return session


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    roles = Column(String, nullable=False)


class Article(Base):
    __tablename__ = 'articles'
    id = Column(Integer, primary_key=True)
    authors = Column(String, nullable=False)  # emails
    editors = Column(String)  # emails
    status = Column(String, nullable=False)
    rating = Column(Integer)
    readers = Column(Integer)
    title = Column(String, nullable=False)
    text = Column(Text, nullable=False)
    tags = Column(String, nullable=False)
    created_at = Column(String, default=datetime.utcnow())
    section_id = Column(String, ForeignKey('sections.id'))


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    text = Column(String, nullable=False)


class Section(Base):
    __tablename__ = 'sections'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    created_by_id = Column(Integer, ForeignKey('users.id'))


class Token(Base):
    __tablename__ = 'auth_tokens'
    id = Column(Integer, primary_key=True)
    used_id = Column(Integer, ForeignKey('users.id'))
    token = Column(String, nullable=False)
    created_at = Column(String, default=datetime.utcnow())
