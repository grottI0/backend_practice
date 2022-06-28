from datetime import timedelta, datetime
from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from forms import SignUpForm, Token, DraftForm, TokenData
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


def get_authors(s: str):
    l = s.split(' ')
    result = []
    for i in range(len(l) - (len(l)//2)):
        try:
            l[i], l[i+1] = l[i].capitalize(), l[i+1].capitalize()
            l[i] = l[i] + ' ' + l[i+1]
            l.remove(l[i+1])
        except IndexError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='incorrect input',
                                headers={'WWW-Authenticate': 'Bearer'})
        result.append(l[i])
    return result


@app.post('/sign_up', name='user:sign_up')
def registration(body: SignUpForm, db=Depends(connection)):
    first_name = body.first_name.capitalize()
    last_name = body.last_name.capitalize()
    full_name = last_name + ' ' + first_name
    email = body.email.lower()
    password = body.password
    role = body.role.lower()
    if first_name == '' or email == '' or password == '' or last_name == '':
        return {'status': 'failed',
                'message': 'empty input field'}

    if role != 'moderator' and role != 'writer' and role != 'reader' and role != 'admin':
        return {'status': 'failed',
                'message': 'wrong role'}
    elif role == 'writer':
        roles = 'writer reader'
    elif role == 'moderator':
        roles = 'moderator writer reader'
    elif role == 'admin':
        roles = 'admin moderator writer reader'
    else:
        roles = 'reader'

    user = db.query(User.id).filter(User.email == body.email).one_or_none()
    if user:
        return {'status': 'failed',
                'message': 'user is already registered'}
    else:
        user = User(full_name=full_name,
                    email=body.email,
                    password=get_password_hash(body.password),
                    roles=roles)
        db.add(user)
        db.commit()

        return {'message': 'user created'}


# авторизация и создание токена для дальнейшей работы
@app.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(connection)):
    email = form_data.username
    user = db.query(User).filter(User.email == email).one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    if not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"email": user.email, 'roles': user.roles, 'full_names': user.full_name},
                                       expires_delta=access_token_expires)

    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/user', name='user:get')
def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(connection)):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                              detail='Could not validate credentials',
                              headers={'WWW-Authenticate': 'Bearer'})
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        email: str = payload['email']
        roles: str = payload['roles']
        full_name: str = payload['full_name']
        if email is None or roles is None or full_name is None:
            raise exception
        token_data = TokenData(email=email, roles=roles)
    except JWTError:
        raise exception

    user = db.query(User).filter(User.email == token_data.email).one_or_none()
    if user is None:
        raise exception

    return user


@app.get('/article/create_draft')
def get_draft_creation(token=Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        roles: str = payload['roles']

        if roles is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='incorrect data',
                                headers={'WWW-Authenticate': 'Bearer'})
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='incorrect data',
                            headers={'WWW-Authenticate': 'Bearer'})
    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='inappropriate role',
                            headers={'WWW-Authenticate': 'Bearer'})

    return {"status": status.HTTP_200_OK}


@app.post('/article/create_draft')
def create_article(body: DraftForm, db=Depends(connection), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        roles: str = payload['roles']

        if roles is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='incorrect data',
                                headers={'WWW-Authenticate': 'Bearer'})
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='incorrect data',
                            headers={'WWW-Authenticate': 'Bearer'})
    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='inappropriate role',
                            headers={'WWW-Authenticate': 'Bearer'})
    authors = get_authors(body.authors)
    for i in range(len(authors)):
        user = db.query(User).filter(User.full_name == authors[i])
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='incorrect data',
                                headers={'WWW-Authenticate': 'Bearer'})

    article = Article(title=body.title,
                      text=body.text,
                      tags=body.tags,
                      authors=' '.join(authors),
                      status='draft')
    db.add(article)
    db.commit()

    return {'message': 'draft created'}


@app.get('/article/edit_draft/{title}')
def get_draft(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    pass
    # возвращает текст, теги


@app.post('/article/edit_draft/{title}')
def edit_draft(title, token, db):
    pass
    # принимает текст теги и записывает в бд


@app.get('/article/{title}')
def get_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    pass
    # возвращает название, авторов, теги, секцию и все комментарии
