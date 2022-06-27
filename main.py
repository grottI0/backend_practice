import hashlib
from datetime import timedelta

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette import status

from forms import SignUpForm, SignInForm, Token
from database import connection, User
from config import KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from security import authenticate_user, create_access_token, get_current_user


def hashed(password):
    return hashlib.sha256(f'{KEY}{password}'.encode('utf8')).hexdigest()


'''def check_token(token, db=Depends(connection)):
    auth_token = db.query(Token).filter(token == Token.token).one_or_none()
    if auth_token:
        return auth_token
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='authentication is failed')'''


app = FastAPI()
# session = connection()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


@app.post('/sign_up', name='user:sign_up')
def registration(body: SignUpForm, db=Depends(connection)):
    first_name = body.first_name.capitalize()
    last_name = body.last_name.capitalize()
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


@app.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(connection)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"email": user.email, 'roles': user.roles}, expires_delta=access_token_expires
    )
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/user', name='user:get')
def get_current_user(current_user: User = Depends(get_current_user)):
    return current_user
