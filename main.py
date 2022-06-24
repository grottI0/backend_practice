from fastapi import FastAPI

from forms import SignUpForm, SignInForm


app = FastAPI()


@app.post('/reg', name='user:creation')
def registration(body: SignUpForm):
    name = body.name.lower()
    email = body.email.lower()
    login = body.login
    password = body.password
    roles = body.roles.split()
    for i in roles:
        i = i.lower()
        if i != 'moderator' and i != 'writer' and i != 'reader' and i != 'admin':
            return {'status': 'failed'}
    if name == '' or email == '' or login == '' or password == '':
        return {'status': 'failed'}

    return {'status': 'ok'}
