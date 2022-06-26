import hashlib, uuid

from fastapi import FastAPI, Depends, HTTPException
from starlette import status

from forms import SignUpForm, SignInForm
from database import connection, User, Token
from config import KEY


def hashed(password):
    return hashlib.sha256(f'{KEY}{password}'.encode('utf8')).hexdigest()


def check_token(token, db=Depends(connection)):
    auth_token = db.query(Token).filter(token == Token.token).one_or_none()
    if auth_token:
        return auth_token
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='authentication is failed')


app = FastAPI()
# session = connection()


@app.post('/sign_up', name='user:sign_up')
def registration(body: SignUpForm, db=Depends(connection)):
    first_name = body.first_name.lower()
    last_name = body.last_name.lower()
    email = body.email.lower()
    password = body.password
    roles = body.roles.split()
    if first_name == '' or email == '' or password == '' or last_name == '':
        return {'status': 'failed',
                'message': 'empty input field'}
    for i in roles:
        i = i.lower()
        if i != 'moderator' and i != 'writer' and i != 'reader' and i != 'admin':
            return {'status': 'failed',
                    'message': 'wrong role'}

    user = db.query(User.id).filter(User.email == body.email).one_or_none()
    if user:
        return {'status': 'failed',
                'message': 'user is already registered'}
    else:
        user = User(first_name=body.first_name,
                    last_name=body.last_name,
                    email=body.email,
                    password=hashed(body.password),
                    roles=body.roles)
        db.add(user)

    db.commit()

    return {'status': 'ok'}


@app.post('/user', name='user:sign_in')
def sign_in(body: SignInForm, db=Depends(connection)):
    email = body.email
    password = body.password
    if email == '' or password == '':
        return {'status': 'failed',
                'message': 'empty input field'}

    user = db.query(User).filter(User.email == body.email).one_or_none()
    if not user or (hashed(body.password) != user.password):
        return {'status': 'failed',
                'message': 'email or password is invalid'}
    token = Token(token=str(uuid.uuid4()), user_id=user.id)
    db.add(token)
    db.commit()

    return {'status': 'ok'}


'''@app.get('/user', name='user:get')
def get_user(token: Token = Depends(check_token), db=Depends(connection)):
    user = db.query(User).filter(User.id == Token.user_id).one_or_none()
    
    return {'status': 'ok',
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'roles': user.roles}'''
