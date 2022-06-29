from datetime import timedelta, datetime
from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_

from forms import SignUpForm, Token, DraftCreateForm, DraftEditForm, TokenData
from database import connection, User, Article
from config import ALGORITHM, KEY, ACCESS_TOKEN_EXPIRE_MINUTES


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(email, password, db=Depends(connection)):
    user = db.query(User).filter(User.email == email).one_or_none()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    print(to_encode)
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_full_names_list(s: str):
    l = s.split(' ')
    result = []
    for i in range(len(l) - (len(l) // 2)):
        try:
            l[i], l[i + 1] = l[i].capitalize(), l[i + 1].capitalize()
            l[i] = l[i] + ' ' + l[i + 1]
            l.remove(l[i + 1])
        except IndexError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        result.append(l[i])
    return result


def get_token_payload(token, db):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        for key, value in payload.items():
            if key is None or value is None:
                raise exception
        token_data = TokenData(email=payload['email'],
                               roles=payload['roles'],
                               full_name=payload['full_name'])
    except JWTError:
        raise exception

    user = db.query(User).filter(and_(User.email == token_data.email,
                                 User.full_name == token_data.full_name,
                                 User.roles == token_data.roles)).one_or_none()
    if user is None:
        raise exception

    return payload


@app.post('/sign_up', name='user:sign_up')
def registration(body: SignUpForm, db=Depends(connection)):
    first_name = body.first_name.capitalize()
    last_name = body.last_name.capitalize()
    full_name = last_name + ' ' + first_name
    email = body.email.lower()
    password = body.password
    roles = body.roles.lower()
    if first_name == '' or email == '' or password == '' or last_name == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if 'moderator' not in roles and \
            'writer' not in roles and \
            'reader' not in roles and \
            'admin' not in roles:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    if roles == 'admin':
        roles = 'reader writer moderator'

    user = db.query(User.id).filter(User.email == body.email).one_or_none()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    else:
        user = User(full_name=full_name,
                    email=body.email,
                    password=get_password_hash(body.password),
                    roles=roles)
        db.add(user)
        db.commit()

        return {'status': status.HTTP_200_OK}


# авторизация и создание токена для дальнейшей работы
@app.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(connection)):
    email = form_data.username
    user = db.query(User).filter(User.email == email).one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"email": user.email, 'roles': user.roles, 'full_name': user.full_name},
                                       expires_delta=access_token_expires)

    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/user', name='user:get')
def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    email = payload['email']
    user = db.query(User).filter(User.email == email).one_or_none()

    return user


@app.get('/article/create_draft')
def get_draft_creation(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    roles = payload['roles']
    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return {"status": status.HTTP_200_OK}


@app.post('/article/create_draft')
def create_article(body: DraftCreateForm, db=Depends(connection), token: str = Depends(oauth2_scheme)):
    payload = get_token_payload(token, db)
    roles = payload['roles']
    creator = payload['full_name']

    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    authors = get_full_names_list(body.authors)
    if creator not in authors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    for i in range(len(authors)):
        user = db.query(User).filter(User.full_name == authors[i]).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    article = Article(creator=payload['full_name'],
                      title=body.title,
                      text=body.text,
                      tags=body.tags,
                      authors=' '.join(authors),
                      status='draft')
    db.add(article)
    db.commit()

    return {'message': 'draft created',
            'title': body.title}


@app.get('/article/edit_draft/{title}')
def get_draft(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user = payload['full_name']

    article = db.query(Article).filter(and_(Article.title == title,
                                       Article.status == 'draft')).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user not in article.authors:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return {'draft_text': article.text,
            'draft_tags': article.tags}


@app.post('/article/edit_draft/{title}')
def edit_draft(title, body: DraftEditForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user = payload['full_name']

    draft = db.query(Article).filter(and_(Article.title == title,
                                     Article.status == 'draft')).one_or_none()

    if draft is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user not in draft.authors:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    draft.text = body.text
    draft.tags = body.tags
    db.commit()


@app.post('/article/publish/{title}')
def publish_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user = payload['full_name']
    article = db.query(Article).filter(and_(Article.creator == current_user, Article.title == title)).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    article.status = 'published'
    db.commit()
    return {'status': status.HTTP_200_OK}


@app.get('/articles/published')
def list_to_approve(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    articles = db.query(Article).filter(Article.status == 'published').all()
    response = {}
    for i in articles:
        response.update({i.title: {'creator': i.creator,
                                   'authors': i.authors,
                                   'text': i.text,
                                   'tags': i.tags}})
    return response


@app.post('/article/approve/{title}')
def approve_article(title, edited: bool, other_editors: Union[str or None],
                    token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(and_(Article.title == title,
                                       Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if edited:
        editors = get_full_names_list(other_editors)
        for i in editors:
            user = db.query(User).filter(User.full_name == i).one_or_none()
            if user is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        article.editors += payload['full_name'] + ' ' + other_editors

    article.status = 'approved'
    db.commit()

    return {'status': status.HTTP_200_OK}


@app.post('/article/reject/{title}')
def reject_article(title, message: str, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(and_(Article.title == title,
                                       Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    message = f' {payload["full_name"]}: {message}'
    article.status = 'rejected'
    article.text += message
    db.commit()


@app.get('/article/{title}')
def get_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    pass
    # возвращает название, авторов, теги, секцию и все комментарии
