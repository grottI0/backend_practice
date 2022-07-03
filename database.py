from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, BOOLEAN
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

from config import DB_URL


Base = declarative_base()


def connection():
    engine = create_engine(DB_URL)
    session = Session(bind=engine.connect())
    return session


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    roles = Column(String, nullable=False)
    blocked = Column(BOOLEAN, default=False)


class Article(Base):
    __tablename__ = 'articles'
    id = Column(Integer, primary_key=True)
    creator = Column(String, nullable=False)
    authors = Column(String, nullable=False)
    editors = Column(String)
    status = Column(String, nullable=False)
    rating = Column(Integer)
    readers = Column(Integer)
    title = Column(String, nullable=False)
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
    name = Column(String, nullable=False)
    creator_id = Column(Integer, ForeignKey('users.id'))


class Rating(Base):
    __tablename__ = 'ratings'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    rating = Column(Integer, nullable=False)
