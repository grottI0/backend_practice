from fastapi import FastAPI, Depends

from forms import SignUpForm, SignInForm
from database import connection, User


app = FastAPI()
# session = connection()


@app.post('/sign_up', name='user:sign_up')
def registration(body: SignUpForm, database=Depends(connection)):
    first_name = body.first_name.lower()
    last_name = body.last_name.lower()
    email = body.email.lower()
    login = body.login
    password = body.password
    roles = body.roles.split()
    for i in roles:
        i = i.lower()
        if i != 'moderator' and i != 'writer' and i != 'reader' and i != 'admin':
            return {'status': 'failed'}
    if first_name == '' or email == '' or password == '' or last_name == '' or login == '':
        return {'status': 'failed'}

    return {'status': 'ok'}


@app.post('/sign_in', name='user:sign_in')
def sign_in(body: SignInForm, database=Depends(connection)):
    login = body.login
    password = body.password
    if login == '' or password == '':
        return {'status': 'failed',
                'message': 'empty input field'}
    user = database.query()

    return {'status': 'ok'}
