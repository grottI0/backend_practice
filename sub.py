from fastapi import FastAPI, Request


app = FastAPI()


@app.get('/qwerty')
def func(request: Request):
    print(request.query_params, type(request.query_params))
    params = str(request.query_params)
    print(params)
    if 'code' in params:
        params = params.split('=')
        print(params[1])
