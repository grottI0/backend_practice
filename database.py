import os

from sqlalchemy import create_engine, MetaData, Column, Integer, String, ForeignKey, Text, BOOLEAN
from sqlalchemy.orm import Session, relationship
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


def create_table():
    Base.metadata.create_all()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    roles = Column(String)
    blocked = Column(BOOLEAN, default=False)
    vk_id = Column(String, unique=True)

    sections = relationship('Section', back_populates='creator', cascade='all, delete', passive_deletes=True)
    comments = relationship('Comment', back_populates='creator', cascade='all, delete', passive_deletes=True)
    ratings = relationship('Rating', back_populates='creator', cascade='all, delete', passive_deletes=True)
    sessions = relationship('SessionTable', back_populates='creator', cascade='all, delete', passive_deletes=True)


class Section(Base):
    __tablename__ = 'sections'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    creator_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))

    creator = relationship('User', back_populates='sections')
    articles = relationship('Article', back_populates='section', passive_deletes=True)


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
    section_id = Column(Integer, ForeignKey('sections.id', ondelete='SET NULL'), nullable=True)
    number_of_ratings = Column(Integer)

    section = relationship('Section', back_populates='articles')
    comments = relationship('Comment', back_populates='article', passive_deletes=True)
    ratings = relationship('Rating', back_populates='article', passive_deletes=True)


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id', ondelete='CASCADE'))
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    text = Column(String, nullable=False)

    creator = relationship('User', back_populates='comments')
    article = relationship('Article', back_populates='comments')


class Rating(Base):
    __tablename__ = 'ratings'
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('articles.id', ondelete='CASCADE'))
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    rating = Column(Integer, nullable=False)

    creator = relationship('User', back_populates='ratings')
    article = relationship('Article', back_populates='ratings')


class SessionTable(Base):
    __tablename__ = 'sessions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    session_id = Column(String, nullable=False, unique=True)

    creator = relationship('User', back_populates='sessions')
