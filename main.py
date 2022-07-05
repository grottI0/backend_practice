from datetime import timedelta, datetime
from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_, or_
from pydantic import conint

from forms import SignUpForm, Token, DraftCreateForm, DraftEditForm, TokenData, ApprovedEditForm, RejectForm
from database import connection, User, Article, Comment, Rating, Section
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

    expire = datetime.utcnow() + expires_delta
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
                               blocked=payload['blocked'])
    except JWTError:
        raise exception

    user = db.query(User).filter(and_(User.id == token_data.id,
                                      User.roles == token_data.roles,
                                      User.blocked == token_data.blocked)).one_or_none()
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
                                             'roles': user.roles,
                                             'blocked': user.blocked},
                                       expires_delta=access_token_expires)

    return {'access_token': access_token, 'token_type': 'bearer'}


# Создание черновика(статьи) и добавление в базу данных
@app.post('/article/create_draft')
def create_article(body: DraftCreateForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    creator_id = str(payload['id'])

    if 'writer' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    body.other_authors = body.other_authors
    other_authors_ids = body.other_authors.split()

    for i in range(len(other_authors_ids)):
        user = db.query(User).filter(User.id == other_authors_ids[i]).one_or_none()
        if user is None or user.id == payload['id']:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        elif 'writer' not in user.roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    authors = f'{creator_id} {" ".join(other_authors_ids)}'

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
@app.get('/article/get_disapproved')
def get_disapproved(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    article = db.query(Article).filter(and_(Article.title == title,
                                            or_(Article.status == 'draft',
                                                Article.status == 'rejected'))).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif current_user_id not in article.authors.split() or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if article.status == 'rejected':
        article.status = 'draft'
        db.commit()

    return {'text': article.text,
            'tags': article.tags}


# Отправка отредактированного черновика и его обновление в базе данных
@app.post('/article/edit_draft')
def edit_draft(body: DraftEditForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    current_user_id = str(payload['id'])

    draft = db.query(Article).filter(and_(Article.title == body.title,
                                          Article.status == 'draft')).one_or_none()

    if draft is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    elif (current_user_id not in draft.authors.split() and current_user_id not in draft.editors.split()) \
            or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    draft.text = body.text
    draft.tags = body.tags
    db.commit()

    return {'status': status.HTTP_200_OK}


# Смена состояния статьи на "опубликована"
@app.get('/article/publish')
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


# Получение статей в состоянии "опубликлвана" (для модераторов и админов)
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
# если не требуется исправление в поля edited_text и other_editors отправляется пустая строка
# если модератор является единственным редактором в поле other_editors отправляется пустая строка
@app.post('/article/approve')
def approve_article(body: ApprovedEditForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(and_(Article.title == body.title,
                                            Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if body.edited_text != '':
        article.text = body.edited_text

    other_editors_ids = body.other_editors.split()
    for i in other_editors_ids:
        user = db.query(User).filter(User.id == i).one_or_none()
        if user is None or (user.id == payload['id']):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        elif article.editors is not None:
            if str(user.id) in article.editors:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        elif 'moderator' not in user.roles and 'writer' not in user.roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article.editors = f'{str(payload["id"])} {" ".join(other_editors_ids)}'

    article.status = 'approved'
    article.readers = article.rating = article.number_of_ratings = 0
    article.approved_at = datetime.utcnow()
    db.commit()

    return {'status': status.HTTP_200_OK}


# Смена состояния статьи на "отклонена"
@app.post('/article/reject')
def reject_article(body: RejectForm, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(and_(Article.title == body.title,
                                            Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    moderators_email = db.query(User.email).filter(User.id == payload['id']).one_or_none()
    message = f' !MESSAGE FROM MODERATOR ({moderators_email}): {body.message}'
    article.status = 'rejected'
    article.text += message
    db.commit()

    return {'status': status.HTTP_200_OK}


# Смена состояния из "отклонена" или "опубликована" на "черновик"
@app.get('/article/to_draft')
def to_draft(title, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    article = db.query(Article).filter(Article.title == title).one_or_none()
    if article is None or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    if str(payload['id']) not in article.authors.split():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if article.status == 'approved' or article.status == 'rejected':
        article.status = 'draft'
        article.approved_at = None
        db.commit()

        return {'status': status.HTTP_200_OK}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


# Добавление читателем коментария к статье и его оценка этой статьи
@app.post('/article/create_comment')
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
@app.get('/article/delete_comment')
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
@app.get('/user')
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
        if str(user.id) in i.authors.split():
            count += 1
            titles.update({count: i.title})

    return {'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'blocked': payload['blocked'],
            'roles': user.roles,
            'articles': titles}


# Меняет статус пользователя на
# "заблокирован" (в этом случае удаляет комментарии и оценки пользователя, а его статус его статей изменяет на черновик)
# или "не заблокирован"
@app.get('/user/{block_or_unblock}}')
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
@app.get('/article')
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
                'date': article.approved_at,
                'comments': {}}

    comments = {}
    for i in comments_list:
        comment = {i[0]: {'text': i[1], 'user_id': i[2], 'full_name': i[3]}}
        comments.update(comment)
    response.update({'comments': comments})

    return response


@app.get('/articles')
def search_articles(rating: str = None, number_of_readers: str = None, title: str = None,
                    content: str = None, tags: str = None, authors: str = None,
                    date: str = None, section_name: str = None,
                    token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'reader' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if rating:
        articles = db.query(Article).filter(and_(Article.status == 'approved',
                                                 Article.rating == rating)).all()
    elif number_of_readers:
        articles = db.query(Article).filter(and_(Article.status == 'approved',
                                                 Article.readers == number_of_readers)).all()
    elif title:
        article = db.query(Article).filter(and_(Article.status == 'approved',
                                                Article.title == title)).one_or_none()
        articles = [article]
    elif content:
        all_articles = db.query(Article).filter(Article.status == 'approved').all()
        articles = []
        for i in all_articles:
            if content.lower() in i.text.lower():
                articles.append(i)
    elif tags:
        all_articles = db.query(Article).filter(Article.status == 'approved').all()
        articles = []
        tags_list = tags.split()
        for i in all_articles:
            for j in tags_list:
                if j in i.tags:
                    articles.append(i)
    elif authors:
        all_articles = db.query(Article).filter(Article.status == 'approved').all()
        articles = []
        authors_ids = authors.split()
        for i in all_articles:
            for j in authors_ids:
                if j in i.authors:
                    articles.append(i)
    elif date:
        all_articles = db.query(Article).filter(Article.status == 'approved').all()
        articles = []
        for i in all_articles:
            if i.approved_at[:10] == date:
                articles.append(i)

    elif section_name:
        section = db.query(Section).filter(Section.name == section_name).one_or_none()
        articles = db.query(Article).filter(and_(Article.section_id == section.id,
                                                 Article.status == 'approved')).all()
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    response = {}

    for i in articles:
        response.update({i.id: i.title})

    return response


@app.get('/articles/new')
def get_new_articles(token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)
    if payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    articles = db.query(Article).filter(Article.status == 'approved').order_by(Article.approved_at.desc()).all()
    if articles is None:
        return {}

    response = {}
    today = datetime.utcnow()
    for i in articles:
        delta = today - datetime.strptime(i.approved_at[:10], '%Y-%m-%d')
        if delta.days <= 3:
            response.update({i.approved_at: {'id': i.id, 'title': i.title, 'tags': i.tags}})
        else:
            break
    return response


@app.get('/article/rate')
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


# создание секции
@app.get('/section/create')
def create_section(name, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    section = Section(name=name,
                      creator_id=payload['id'])

    db.add(section)
    db.commit()

    return {'status': status.HTTP_200_OK}


# добавление статьи в секцию
@app.get('/article/add_to_section')
def add_to_section(title, name, token=Depends(oauth2_scheme), db=Depends(connection)):
    payload = get_token_payload(token, db)

    if 'moderator' not in payload['roles'] or payload['blocked']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    article = db.query(Article).filter(Article.title == title).one_or_none()
    section = db.query(Section).filter(Section.name == name).one_or_none()

    if article is None or section is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    article.section_id = section.id
    db.commit()

    return {'status': status.HTTP_200_OK}
