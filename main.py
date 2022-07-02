from datetime import timedelta, datetime
from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_, or_
from pydantic import conint

from forms import SignUpForm, Token, DraftCreateForm, DraftEditForm, TokenData
from database import connection, User, Article, Comment, Rating
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
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_token_payload(token, db):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    try:
        payload = jwt.decode(token, KEY, algorithms=[ALGORITHM])
        for key, value in payload.items():
            if key is None or value is None:
                raise exception
        token_data = TokenData(id=payload['id'],
                               roles=payload['roles'],
                               full_name=payload['full_name'],
                               blocked=payload['blocked'])
    except JWTError:
        raise exception

    user = db.query(User).filter(and_(User.id == token_data.id,
                                      User.roles == token_data.roles,
                                      User.full_name == token_data.full_name,
                                      User.blocked == token_data.blocked)).one_or_none()
    if user is None:
        raise exception

    return payload


def get_full_names_list(s: str):
    words_list = s.split(' ')
    result = []
    for i in range(len(words_list) - (len(words_list) // 2)):
        try:
            words_list[i], words_list[i + 1] = words_list[i].capitalize(), words_list[i + 1].capitalize()
            words_list[i] = words_list[i] + ' ' + words_list[i + 1]
            words_list.remove(words_list[i + 1])
        except IndexError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        result.append(words_list[i])
    return result


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
                                             'roles': user.roles,
                                             'full_name': user.full_name,
                                             'blocked': user.blocked},
                                       expires_delta=access_token_expires)

    return {'access_token': access_token, 'token_type': 'bearer'}


# -
@app.get('/article/create_draft')
def get_draft_creation(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    roles = payload['roles']
    if 'writer' not in roles or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return {"status": status.HTTP_200_OK}


# Создание черновика(статьи) и добавление в базу данных
@app.post('/article/create_draft')
def create_article(body: DraftCreateForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    creator_id = str(payload['id'])

    if 'writer' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if body.other_authors != 'None':
        other_authors = get_full_names_list(body.other_authors)
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
@app.get('/article/get_disapproved/{title}')
def get_disapproved(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    article = db.query(Article).filter(and_(Article.title == title,
                                            or_(Article.status == 'draft',
                                                Article.status == 'rejected'))).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user_id not in article.authors or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if article.status == 'rejected':
        article.status = 'draft'
        db.commit()

    return {'text': article.text,
            'tags': article.tags}


# Отправка отредактированного черновика и его обновление в базе данных
@app.post('/article/edit_draft/{title}')
def edit_draft(title, body: DraftEditForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    draft = db.query(Article).filter(and_(Article.title == title,
                                          Article.status == 'draft')).one_or_none()

    if draft is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif (current_user_id not in draft.authors and current_user_id not in draft.editors) or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    draft.text = body.text
    draft.tags = body.tags
    db.commit()

    return {'status': status.HTTP_200_OK}


# Смена состояния статьи на "опубликована"
@app.get('/article/publish/{title}')
def publish_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])
    article = db.query(Article).filter(and_(Article.creator == current_user_id, Article.title == title)).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    elif payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article.status = 'published'
    db.commit()
    return {'status': status.HTTP_200_OK}


# Получение данных о статьях в состоянии "опубликлвана" (для модераторов и админов)
@app.get('/articles/published')
def list_to_approve(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
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

    if 'moderator' not in payload['roles'] or payload['blocked']:
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
            other_editors_list = get_full_names_list(other_editors)
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

    if 'moderator' not in payload['roles'] or payload['blocked']:
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
    if article is None or payload['blocked']:
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
def create_comment(title, text: str, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'reader' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    current_user = db.query(User).filter(User.id == payload['id']).one_or_none()

    article = db.query(Article).filter(and_(Article.title == title,
                                            Article.status == 'approved')).one_or_none()

    if current_user is None or article is None or text == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    comment = Comment(text=text,
                      article_id=article.id,
                      user_id=current_user.id)
    db.add(comment)
    db.commit()

    return {'status': status.HTTP_200_OK}


# Удаление комментария из базы данных
@app.get('/article/delete_comment/{comment_id}')
def delete_comment(comment_id, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    comment = db.query(Comment).filter(Comment.id == comment_id).one_or_none()
    if comment is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    author_id = comment.user_id

    current_user_id = db.query(User.id).filter(User.id == payload['id']).one_or_none()
    if ('moderator' not in payload['roles'] and author_id != current_user_id) or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(Article.id == comment.article_id).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    db.query(Comment).filter(Comment.id == comment_id).delete()
    db.commit()

    return {'status': status.HTTP_200_OK}


# Получение данных о пользователе по его id
@app.get('/user/{user_id}')
def get_any_user(user_id, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if not token or (payload['blocked'] and user_id != payload['id']):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    user = db.query(User).filter(User.id == user_id).one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    articles = db.query(Article.authors, Article.title).all()
    titles = {}
    count = 0

    for i in articles:
        if str(user.id) in i.authors:
            titles.update({count + 1: i.title})

    return {'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'blocked': payload['blocked'],
            'roles': user.roles,
            'articles': titles}


# Меняет статус пользователя на "заблокирован" или "не заблокирован"
@app.get('/user/{user_id}/{block_or_unblock}}')
def blocking_user(user_id, operation, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    user = db.query(User).filter(and_(User.id == user_id, User.id != payload['id'])).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if operation == 'block':
        user.blocked = True
        db.query(Comment).filter(Comment.user_id == user.id).delete()
        articles = db.query(Article).filter(Article.creator == str(user.id)).all()
        for i in articles:
            i.status = 'draft'

        ratings = db.query(Rating).filter(Rating.user_id == user.id).all()
        if ratings is None:
            pass
        else:
            for i in ratings:
                rated_article = db.query(Article).filter(Article.id == i.article_id).one_or_none()
                try:
                    rated_article.rating = (rated_article.rating * rated_article.number_of_ratings - i.rating) // \
                                           (rated_article.number_of_ratings - 1)
                except ZeroDivisionError:
                    rated_article.rating = 0
                rated_article.number_of_ratings -= 1

        db.query(Rating).filter(Rating.user_id == user.id).delete()

    elif operation == 'unblock':
        user.blocked = False
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    db.commit()

    return {'status': status.HTTP_200_OK}


# Получение данных о статье и ее комментариев
@app.get('/article/{title}')
def get_article(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    current_user_id = db.query(User.id).filter(User.id == payload['id']).one_or_none()

    if not token or current_user_id is None or payload['blocked'] or 'reader' not in payload['roles']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(Article.title == title).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    article.readers += 1
    db.commit()

    comments_list = db.query(Comment.id,
                             Comment.text,
                             Comment.user_id,
                             User.full_name).join(User).filter(Comment.article_id == article.id).all()

    if comments_list is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    authors = ''
    authors_ids = article.authors.split()
    for i in authors_ids:
        user = db.query(User.full_name).filter(User.id == i).one_or_none()
        authors += user[0] + ' '

    response = {'title': article.title,
                'authors': authors,
                'tags': article.tags,
                'number_of_readers': article.readers,
                'text': article.text,
                'created_at': article.created_at,
                'comments': {}}

    comments = {}
    for i in comments_list:
        comment = {i[0]: {'user_id': i[3], 'full_name': i[2], 'text': i[1]}}
        comments.update(comment)
    response.update({'comments': comments})

    return response


@app.get('/articles')
def get_articles(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    if payload['blocked']:
        HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    articles = db.query(Article).filter(Article.status == 'approved').all()
    response = {}

    for i in articles:
        response.update({i.id: {'title': i.title,
                                'tags': i.tags}})

    return response


@app.get('/article/{title}/rate')
def rate_article(title, rating: conint(gt=0, lt=6), token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'reader' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(Article.title == title).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    existed_rating = db.query(Rating).filter(and_(Rating.user_id == payload['id'],
                                                  Rating.article_id == article.id)).one_or_none()
    if not(existed_rating is None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    article.rating = (article.rating * article.number_of_ratings + rating) // (article.number_of_ratings + 1)
    article.number_of_ratings += 1

    row = Rating(user_id=payload['id'],
                 article_id=article.id,
                 rating=rating)

    db.add(row)
    db.commit()

    return {'status': status.HTTP_200_OK}
