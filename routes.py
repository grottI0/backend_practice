import os
from datetime import datetime
from typing import Union
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status, Cookie, Request, Form
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import and_, or_
from sqlalchemy.exc import DataError, IntegrityError
from pydantic import conint
import requests

from forms import SignUpForm, DraftCreateForm, DraftEditForm, ApprovedEditForm, RejectForm, SignInForm, ChangeRolesForm
from database import connection, User, Article, Comment, Rating, Section, SessionTable as Session


router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db_session = connection()
templates = Jinja2Templates(directory="templates")


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_current_user(session_id):
    if session_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='You do not have session id')

    user = db_session.query(User).join(Session).filter(and_(Session.session_id == session_id,
                                                            Session.user_id == User.id)).one_or_none()
    if user is None:
        if '$' in session_id:
            user_id, access_token = session_id.split('$')[0], session_id.split('$')[1]
            r = requests.get(
                url=f'https://api.vk.com/method/users.get?user_ids={user_id}&access_token={access_token}&v=5.131')
            try:
                if r.json()['response']:
                    user = db_session.query(User).filter(User.vk_id == user_id).one_or_none()
                    if user is None:
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                            detail='User does not exist or wrong vk token')
            except KeyError:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail='Wrong vk token')
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='User does not exist')

    return user


# Добавление пользователя в базу данных
@router.post('/sign_up',  tags=['main'])
def registration(body: SignUpForm,):
    first_name = body.first_name.capitalize()
    last_name = body.last_name.capitalize()
    full_name = last_name + ' ' + first_name
    email = body.email.lower()
    password = body.password
    if first_name == '' or email == '' or password == '' or last_name == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Empty input field')

    if body.admin:
        roles = 'reader writer moderator'
    else:
        roles = 'reader'

    user = db_session.query(User.id).filter(User.email == body.email).one_or_none()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='User with this email already exists')
    else:
        user = User(full_name=full_name,
                    email=body.email,
                    password=get_password_hash(body.password),
                    roles=roles)
        db_session.add(user)
        db_session.commit()
        return {'message': 'user created'}


# Создание сессии пользователя, авторизация
@router.post('/sign_in',  tags=['main'])
def sign_in(body: SignInForm):
    user = db_session.query(User).filter(User.email == body.email).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User with this email does not exist')

    if not verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Wrong password')

    content = {'message': 'session created'}
    response = JSONResponse(content=content)
    session_id = str(uuid4())
    response.set_cookie(key="session_id", value=session_id, httponly=True, secure=True)

    session = Session(user_id=user.id,
                      session_id=session_id)
    db_session.add(session)
    db_session.commit()

    return response


# Ссылка для авторизации через ВК
@router.get('/auth_with_vk', tags=['html_only'])
def auth_with_vk(request: Request):
    client_id = os.environ['VK_ID']
    return templates.TemplateResponse('vk_auth.html', {'request': request, 'client_id': client_id})


# Обработка ответа от VK API
@router.get('/vklogin', tags=['dont use'])
def vklogin(code, request: Request):
    if not code:
        return {'message': 'no code'}
    client_id = str(os.environ['VK_ID'])
    secret_key = os.environ['VK_SECRET_KEY']
    body = {'client_id': client_id,
            'client_secret': secret_key,
            'redirect_uri': 'https://backendgrotio.herokuapp.com/vklogin',
            'code': code}
    res = requests.get(url=f'https://oauth.vk.com/access_token', params=body, allow_redirects=True)
    if res.status_code != 200:
        print(res.json())
        return {'message': 'failed'}
    res = res.json()
    if not res['access_token']:
        return {'message': 'no token'}

    user = db_session.query(User).filter(User.vk_id == str(res['user_id'])).one_or_none()

    if not user:
        data = requests.get(
            url=f'https://api.vk.com/method/users.get?user_ids={res["user_id"]}&access_token={res["access_token"]}&v=5.131')
        first_name = data.json()['response'][0]['first_name']
        last_name = data.json()['response'][0]['last_name']

        response = templates.TemplateResponse('signup_with_vk.html',
                                              {'request': request, 'first_name': first_name, 'last_name': last_name})
    else:
        response = JSONResponse(content={'message': 'ok'})

    response.set_cookie(key='session_id', value=f"{res['user_id']}${res['access_token']}",
                        expires=res['expires_in'], httponly=True, secure=True)
    return response


# Стоздание пользователя с данными из ВК
@router.post('/sign_up_with_vk', tags=['dont use'])
def sign_up_with_vk(last_name: str = Form(), first_name: str = Form(),
                    email: str = Form(), password: str = Form(),
                    session_id: Union[str, None] = Cookie(default=None)):
    vk_id = session_id.split('$')[0]

    user = db_session.query(User).filter(or_(User.vk_id == vk_id,
                                             User.email == email)).one_or_none()
    if user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User already exists')

    new_user = User(full_name=f'{last_name} {first_name}',
                    email=email,
                    password=get_password_hash(password),
                    roles='reader',
                    vk_id=vk_id)
    db_session.add(new_user)
    db_session.commit()

    return {'message': 'ok'}


# Удаление текущей сессии пользователя из базы данных и куки
@router.get('/logout',  tags=['main'])
def delete_session(session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    content = {'message': 'current session deleted'}
    response = JSONResponse(content=content)
    response.delete_cookie(key='session_id', httponly=True)

    if db_session.query(Session).filter(Session.session_id == session_id).one_or_none():
        db_session.query(Session).filter(Session.session_id == session_id).delete()
        db_session.commit()

    return response


# Удаление всех сессий пользователя из базы данных
@router.get('/logout_all',  tags=['main'])
def delete_all_sessions(session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    content = {'message': 'all sessions deleted'}
    response = JSONResponse(content=content)
    response.delete_cookie(key='session_id', httponly=True)

    db_session.query(Session).filter(Session.user_id == current_user.id).delete()
    db_session.commit()

    return response


# Удаление всех сессий кроме текущей
@router.get('/logout_except_current', tags=['main'])
def delete_other_sessions(session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    content = {'message': 'other sessions deleted'}
    response = JSONResponse(content=content)

    if db_session.query(Session).filter(Session.session_id == session_id).first():
        db_session.query(Session).filter(and_(Session.user_id == current_user.id,
                                              Session.session_id != session_id)).delete()
        db_session.commit()

    return response


# Получение данных о пользователе по его id
@router.get('/user', tags=['users'])
def get_any_user(user_id: int, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if current_user.blocked and user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    user = db_session.query(User).filter(User.id == user_id).one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='User with this id does not exist')

    articles = db_session.query(Article.authors, Article.title, Article.status).all()
    titles = dict()
    count = 0

    for i in articles:
        if str(user.id) in i.authors.split() and i.status == 'approved':
            count += 1
            titles.update({count: i.title})

    return {'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'blocked': user.blocked,
            'roles': user.roles,
            'articles': titles}


# Меняет статус пользователя на заблокирован, удаляет все комментарии и оценки пользователя,
# а состояние его статей меняет на "черновик"
@router.get('/user/block', tags=['users'])
def block_user(user_id: int, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    user = db_session.query(User).filter(and_(User.id == user_id, User.id != current_user.id)).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='User with this id does not exist')
    user.blocked = True
    db_session.query(Comment).filter(Comment.user_id == user.id).delete()
    articles = db_session.query(Article).filter(Article.creator == str(user.id)).all()
    for i in articles:
        i.status = 'draft'
        i.approved_at = None

    ratings = db_session.query(Rating).filter(Rating.user_id == user.id).all()
    if ratings:
        for i in ratings:
            rated_article = db_session.query(Article).filter(Article.id == i.article_id).one_or_none()
            try:
                rated_article.rating = (rated_article.rating * rated_article.number_of_ratings - i.rating) // \
                                       (rated_article.number_of_ratings - 1)
            except ZeroDivisionError:
                rated_article.rating = 0
            rated_article.number_of_ratings -= 1

    db_session.query(Rating).filter(Rating.user_id == user.id).delete()
    db_session.commit()

    return {'message': 'ok'}


# Меняет статус пользователя на "не заблокирована"
@router.get('/user/unblock', tags=['users'])
def unblock_user(user_id: int, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    user = db_session.query(User).filter(and_(User.id == user_id, User.id != current_user.id)).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='User with this id does not exist')
    user.blocked = False
    db_session.commit()

    return {'message': 'ok'}


# Изменение админом ролей пользователя
@router.post('/user/change_roles', tags=['users'])
def change_roles(body: ChangeRolesForm, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if ('moderator' not in current_user.roles and
            'reader' not in current_user.roles and
            'writer' not in current_user.roles) or \
            current_user.blocked or \
            current_user.id == body.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    user = db_session.query(User).filter(User.id == body.user_id).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='User with this id does not exist')

    if 'reader' not in body.roles and \
            'writer' not in body.roles and \
            'moderator' not in body.roles and \
            'admin' not in body.roles:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect roles input')

    if 'admin' in body.roles:
        body.roles = 'reader writer moderator'

    user.roles = body.roles
    db_session.commit()
    return {'message': 'roles changed'}


# Создание черновика(статьи) и добавление в базу данных
@router.post('/article/create_draft', tags=['articles'])
def create_article(body: DraftCreateForm, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    creator_id = str(current_user.id)

    if 'writer' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    if body.other_authors != '':
        other_authors_ids = body.other_authors.split()

        for i in range(len(other_authors_ids)):
            try:
                user = db_session.query(User).filter(User.id == other_authors_ids[i]).one_or_none()
            except DataError:
                db_session.rollback()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail='Incorrect authors input')

            if user is None or user.id == current_user.id or 'writer' not in user.roles or user.blocked:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail='One of the users cannot be an author')
    else:
        other_authors_ids = []

    authors = f'{creator_id} {" ".join(other_authors_ids)}'

    if not body.title or not body.text or not body.tags:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect input')
    else:
        try:
            article = Article(creator=creator_id,
                              title=body.title,
                              text=body.text,
                              tags=body.tags,
                              authors=authors,
                              status='draft')
        except IntegrityError:
            db_session.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Article already exists')
        else:
            db_session.add(article)
            db_session.commit()

    return {'message': 'draft created',
            'title': body.title}


# Получение данных черновика для дальнейшего редактирования
@router.get('/article/get_disapproved', tags=['articles'])
def get_disapproved(title: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)
    current_user_id = str(current_user.id)

    article = db_session.query(Article).filter(and_(Article.title == title,
                                                    or_(Article.status == 'draft',
                                                        Article.status == 'rejected'))).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This articles does not exist')

    elif (current_user_id not in article.authors.split() and current_user_id not in article.editors.split()) \
            or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    if article.status == 'rejected':
        article.status = 'draft'
        db_session.commit()

    return {'text': article.text,
            'tags': article.tags}


# Отправка отредактированного черновика и его обновление в базе данных
@router.post('/article/edit_draft', tags=['articles'])
def edit_draft(body: DraftEditForm, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)
    current_user_id = str(current_user.id)

    if not body.title or not body.text or not body.tags:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Empty input field')

    article = db_session.query(Article).filter(and_(Article.title == body.title,
                                                    Article.status == 'draft')).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This article does not exist')

    elif (current_user_id not in article.authors.split() and current_user_id not in article.editors.split()) \
            or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article.text = body.text
    article.tags = body.tags
    db_session.commit()

    return {'message': 'draft edited'}


# Смена состояния статьи на "опубликована"
@router.get('/article/publish', tags=['articles'])
def publish_article(title: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)
    current_user_id = str(current_user.id)

    if current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(and_(Article.creator == current_user_id,
                                                    Article.title == title)).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This article does not exist')

    article.status = 'published'
    db_session.commit()

    return {'message': 'article published'}


# Получение статей в состоянии "опубликлвана" (для модераторов и админов)
@router.get('/articles/published', tags=['articles'])
def list_to_approve(session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    articles = db_session.query(Article).filter(Article.status == 'published').all()
    response = dict()
    for i in articles:
        response.update({i.title: {'creator': i.creator,
                                   'authors': i.authors,
                                   'text': i.text,
                                   'tags': i.tags}})

    return response


# Смена состояния статьи на "одобрена" + утверждение числа редакторов и исправление ошибок модератором
# если не требуется исправление в поля edited_text и other_editors отправляется пустая строка
# если модератор является единственным редактором в поле other_editors отправляется пустая строка
@router.post('/article/approve', tags=['articles'])
def approve_article(body: ApprovedEditForm, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')
    if body.title == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Empty title')

    article = db_session.query(Article).filter(and_(Article.title == body.title,
                                                    Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='This article does not exist')

    if body.edited_text != '':
        article.text = body.edited_text

    other_editors_ids = body.other_editors.split()
    for i in other_editors_ids:
        try:
            user = db_session.query(User).filter(User.id == i).one_or_none()
        except DataError:
            db_session.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Incorrect input')

        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='One of editors does not exist')

        elif user.id == current_user.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Do not use your id in "other editors" field')

        elif article.editors:
            if str(user.id) in article.editors:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail='One of the users is already editor of this article')

        elif 'moderator' not in user.roles and 'writer' not in user.roles:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='One of the users cannot be an editor')

    article.editors = f'{str(current_user.id)} {" ".join(other_editors_ids)}'

    article.status = 'approved'
    article.readers = article.rating = article.number_of_ratings = 0
    article.approved_at = datetime.utcnow()
    db_session.commit()
    return {'message': 'article is approved'}


# Смена состояния статьи на "отклонена"
@router.post('/article/reject', tags=['articles'])
def reject_article(body: RejectForm, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(and_(Article.title == body.title,
                                                    Article.status == 'published')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This article does not exist')

    moderators_email = db_session.query(User.email).filter(User.id == current_user.id).one_or_none()
    message = f' !MESSAGE FROM MODERATOR ({moderators_email[0]}): {body.message}'
    article.status = 'rejected'
    article.text += message
    db_session.commit()
    return {'message': 'article is rejected'}


# Смена состояния из "отклонена" или "одобрена" на "черновик"
@router.get('/article/to_draft', tags=['articles'])
def to_draft(title: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    article = db_session.query(Article).filter(Article.title == title).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This article does not exist')

    if str(current_user.id) not in article.authors.split() or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    if article.status == 'approved' or article.status == 'rejected':
        article.status = 'draft'
        article.approved_at = None
        db_session.commit()
        return {'message': 'status changed'}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='Status of this article cannot be changed')


# Добавление читателем коментария к статье
@router.post('/article/create_comment', tags=['articles'])
def create_comment(title: str, text: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'reader' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(and_(Article.title == title,
                                                    Article.status == 'approved')).one_or_none()

    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This article does not exist')

    comment = Comment(text=text,
                      article_id=article.id,
                      user_id=current_user.id)
    db_session.add(comment)
    db_session.commit()
    return {'message': 'comment created'}


# Удаление комментария из базы данных
@router.get('/article/delete_comment', tags=['articles'])
def delete_comment(comment_id: int, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    comment = db_session.query(Comment).filter(Comment.id == comment_id).one_or_none()
    if comment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='This comment does not exist')

    if current_user.blocked or 'moderator' not in current_user.roles or comment.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    db_session.query(Comment).filter(Comment.id == comment_id).delete()
    db_session.commit()
    return {'message': 'comment deleted'}


# поиск статей
@router.get('/article', tags=['articles'])
def get_article(title: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if current_user.blocked or 'reader' not in current_user.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(and_(Article.title == title,
                                                    Article.status == 'approved')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='The article does not exist')
    article.readers += 1
    db_session.commit()

    comments_list = db_session.query(Comment.id,
                                     Comment.text,
                                     Comment.user_id,
                                     User.full_name).join(User).filter(Comment.article_id == article.id).all()

    authors = ''
    authors_ids = article.authors.split()
    for i in authors_ids:
        user = db_session.query(User.full_name).filter(User.id == i).one_or_none()
        authors += user[0] + ' '

    response = {'title': article.title,
                'authors': authors,
                'tags': article.tags,
                'number_of_readers': article.readers,
                'text': article.text,
                'date': article.approved_at,
                'comments': dict()}

    comments = dict()
    for i in comments_list:
        comment = {i[0]: {'text': i[1], 'user_id': i[2], 'full_name': i[3]}}
        comments.update(comment)
    response.update({'comments': comments})
    return response


# поиск статей
@router.get('/articles', tags=['articles'])
def search_articles(rating: str = None, number_of_readers: str = None, title: str = None,
                    content: str = None, tags: str = None, authors: str = None,
                    date: str = None, section_name: str = None,
                    session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'reader' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    if rating:
        articles = db_session.query(Article).filter(and_(Article.status == 'approved',
                                                         Article.rating == rating)).all()
    elif number_of_readers:
        articles = db_session.query(Article).filter(and_(Article.status == 'approved',
                                                         Article.readers == number_of_readers)).all()
    elif title:
        article = db_session.query(Article).filter(and_(Article.status == 'approved',
                                                        Article.title == title)).all()
        articles = [article, ]
    elif content:
        all_articles = db_session.query(Article).filter(Article.status == 'approved').all()
        articles = []
        for i in all_articles:
            if content.lower() in i.text.lower():
                articles.append(i)
    elif tags:
        all_articles = db_session.query(Article).filter(Article.status == 'approved').all()
        articles = []
        tags_list = tags.split()
        for i in all_articles:
            for j in tags_list:
                if j in i.tags.split(', '):
                    articles.append(i)
    elif authors:
        all_articles = db_session.query(Article).filter(Article.status == 'approved').all()
        articles = []
        authors_ids = authors.split()
        for i in all_articles:
            for j in authors_ids:
                if j in i.authors:
                    articles.append(i)
    elif date:
        all_articles = db_session.query(Article).filter(Article.status == 'approved').all()
        articles = []
        for i in all_articles:
            if i.approved_at[:10] == date:
                articles.append(i)

    elif section_name:
        try:
            section = db_session.query(Section).filter(Section.name == section_name).one_or_none()
            if section is None:
                return {}
            articles = db_session.query(Article).filter(and_(Article.section_id == section.id,
                                                             Article.status == 'approved')).all()
        except AttributeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='The section does not exist')
    else:
        articles = db_session.query(Article).filter(Article.status == 'approved').all()

    response = dict()
    if not articles or articles[0] is None:
        return {}

    for i in articles:
        response.update({i.id: i.title})

    return response


# получение названий и айди стаей опубликованных за последние трое суток
@router.get('/articles/new', tags=['articles'])
def get_new_articles(session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)
    if current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    articles = db_session.query(Article).filter(Article.status == 'approved').order_by(Article.approved_at.desc()).all()
    if articles is None:
        return {}

    response = dict()
    today = datetime.utcnow()
    for i in articles:
        delta = today - datetime.strptime(i.approved_at[:10], '%Y-%m-%d')
        if delta.days <= 3:
            response.update({i.approved_at: {'id': i.id, 'title': i.title, 'tags': i.tags}})
        else:
            break

    return response


@router.get('/article/rate', tags=['articles'])
def rate_article(title: str, rating: conint(gt=0, lt=6),
                 session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)
    if 'reader' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(and_(Article.title == title,
                                                    Article.status == 'approved')).one_or_none()
    if article is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='The article does not exist')

    existing_rating = db_session.query(Rating).filter(and_(Rating.user_id == current_user.id,
                                                           Rating.article_id == article.id)).one_or_none()
    if existing_rating:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='You have already rated this article')

    article.rating = int((article.rating * article.number_of_ratings + rating) / (article.number_of_ratings + 1))
    article.number_of_ratings += 1

    row = Rating(user_id=current_user.id,
                 article_id=article.id,
                 rating=rating)
    db_session.add(row)
    db_session.commit()

    return {'message': 'rating created'}


@router.get('/article/add_to_section', tags=['articles'])
def add_to_section(article_title: str, section_name: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    article = db_session.query(Article).filter(Article.title == article_title).one_or_none()
    section = db_session.query(Section).filter(Section.name == section_name).one_or_none()

    if article is None or section is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='The article or section does not exist')

    article.section_id = section.id
    db_session.commit()
    return {'message': 'added to section'}


# Создание секции
@router.get('/section/create', tags=['sections'])
def create_section(name: str, session_id: Union[str, None] = Cookie(default=None)):
    current_user = get_current_user(session_id)

    if 'moderator' not in current_user.roles or current_user.blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Access denied')

    existing_section = db_session.query(Section).filter(Section.name == name)
    if existing_section is None:
        section = Section(name=name,
                          creator_id=current_user.id)

        db_session.add(section)
        db_session.commit()
        return {'message': 'section created'}
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='This section already exists')
