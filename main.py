from datetime import timedelta, datetime
from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_

from forms import SignUpForm, Token, DraftCreateForm, DraftEditForm, TokenData, CommentForm
from database import connection, User, Article, Comment
from config import ALGORITHM, KEY, ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def get_password_hash(password):
    return pwd_context.hash(password)


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
        token_data = TokenData(id=payload['id'],
                               email=payload['email'],
                               roles=payload['roles'],
                               full_name=payload['full_name'])
    except JWTError:
        raise exception

    user = db.query(User).filter(and_(User.id == token_data.id,
                                      User.email == token_data.email,
                                      User.full_name == token_data.full_name,
                                      User.roles == token_data.roles)).one_or_none()
    if user is None:
        raise exception

    return payload


# Добавление пользователя в базу данных
@app.post('/sign_up')
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
    access_token = create_access_token(data={'id': user.id,
                                             'email': user.email,
                                             'roles': user.roles,
                                             'full_name': user.full_name},
                                       expires_delta=access_token_expires)

    return {'access_token': access_token, 'token_type': 'bearer'}


# Получение данных пользователя через токен
@app.get('/user')
def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    user_id = payload['id']
    user = db.query(User).filter(User.id == user_id).one_or_none()

    return user


# -
@app.get('/article/create_draft')
def get_draft_creation(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    roles = payload['roles']
    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return {"status": status.HTTP_200_OK}


# Создание черновика(статьи) и добавление в базу данных
@app.post('/article/create_draft')
def create_article(body: DraftCreateForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    roles = payload['roles']
    creator_id = str(payload['id'])

    if 'writer' not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if body.other_authors != 'None':
        other_authors = body.other_authors.split()
        other_authors_ids = ''

        for i in range(len(other_authors)):
            user = db.query(User).filter(User.full_name == other_authors[i]).one_or_none()
            if user is None or user.id == payload['id']:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

            elif 'writer' not in user.roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

            else:
                other_authors_ids += str(user.id) + ' '

        authors = f'{creator_id} {other_authors_ids}'
    else:
        authors = creator_id

    article = Article(creator=creator_id,
                      title=body.title,
                      text=body.text,
                      tags=body.tags,
                      authors=authors,
                      status='draft')
    db.add(article)
    db.commit()

    return {'message': 'draft created',
            'title': body.title}


# Получение данных черновика для дальнейшего редактирования
@app.get('/article/get_draft/{title}')
def get_draft(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    article = db.query(Article).filter(and_(Article.title == title,
                                            Article.status == 'draft')).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user_id not in article.authors:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return {'draft_text': article.text,
            'draft_tags': article.tags}


# Отправка отредактированного черновика и его обновление в базе данных
@app.post('/article/edit_draft/{title}')
def edit_draft(title, body: DraftEditForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    draft = db.query(Article).filter(and_(Article.title == title,
                                          Article.status == 'draft')).one_or_none()

    if draft is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user_id not in draft.authors and \
            current_user_id not in draft.editors and \
            'writer' not in payload['roles'] and \
            'moderator' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    draft.text = body.text
    draft.tags = body.tags
    db.commit()


# Смена состояния статьи на "опубликована"
@app.get('/article/publish/{title}')
def publish_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    article = db.query(Article).filter(and_(Article.creator == current_user_id, Article.title == title)).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    article.status = 'published'
    db.commit()
    return {'status': status.HTTP_200_OK}


# Получение данных о статьях в состоянии "опубликлвана" (для модераторов и админов)
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


# Смена состояния статьи на "одобрена" + утверждение числа редакторов и исправление ошибок модератором
# если не требуется исправление в поля edited_text и other_editors отправляется строка "None"
# если модератор является единственным редактором в поле other_editors отправляется строка "None"
@app.post('/article/approve/{title}')
def approve_article(title, edited_text: str, other_editors: str,
                    token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(and_(Article.title == title,
                                            Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if edited_text == 'None':
        pass
    elif article.text != edited_text:
        article.text = edited_text
        if other_editors == 'None':
            article.editors = str(payload['id'])
        else:
            other_editors_list = other_editors.split()
            other_editors_ids = ''
            for i in other_editors_list:
                user = db.query(User).filter(User.full_name == i).one_or_none()
                if user is None or (user.id == payload['id']):
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

                elif 'moderator' not in user.roles and 'writer' not in user.roles:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

                else:
                    other_editors_ids += str(user.id) + ' '

            article.editors = f'{str(payload["id"])} {other_editors_ids}'

    article.status = 'approved'
    article.readers = article.rating = article.number_of_ratings = 0
    db.commit()

    return {'status': status.HTTP_200_OK}


# Смена состояния статьи на "отклонена"
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

    return {'status': status.HTTP_200_OK}


# Смена состояния из "отклонена" или "опубликована" на "черновик"
@app.get('/article/to_draft/{title}')
def to_draft(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    article = db.query(Article).filter(Article.title == title).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if str(payload['id']) not in article.authors:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if article.status == 'approved' or article.status == 'rejected':
        article.status = 'draft'
        db.commit()

        return {'status': status.HTTP_200_OK}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


# Добавление читателем коментария к статье и его оценка этой статьи
@app.post('/article/{title}/create_comment')
def create_comment(title, body: CommentForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'reader' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    current_user = db.query(User).filter(User.id == payload['id']).one_or_none()

    article = db.query(Article).filter(and_(Article.title == title,
                                            Article.status == 'approved')).one_or_none()

    if 1 > body.rating > 5 and current_user is None and article is None and body.text == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    article.rating = (article.rating * article.number_of_ratings + body.rating)//(article.number_of_ratings + 1)
    article.number_of_ratings += 1

    comment = Comment(text=body.text,
                      article_id=article.id,
                      user_id=current_user.id)
    db.add(comment)
    db.commit()

    return {'status': status.HTTP_200_OK}


#
@app.get('/article/delete_comment/{comment_id}')
def delete_comment(comment_id, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    comment = db.query(Comment).filter(Comment.id == comment_id).one_or_none()
    if comment is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    author_id = comment.user_id

    current_user_id = db.query(User.id).filter(User.id == payload['id']).one_or_none()

    if 'moderator' not in payload['roles'] and author_id != current_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    db.query(Comment).filter(Comment.id == comment_id).delete()
    db.commit()


@app.get('/article/{title}')
def get_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    pass
    # возвращает название, авторов, теги, секцию и все комментарии
