from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Union
import json
import time
import os
import random

app = FastAPI()

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    token: Union[str, int, None] = "None"
    id: Union[int, None] = -1

class LoginRequest(BaseModel):
    login: str
    password: str

@app.post("/users/auth")
def user_auth(request: LoginRequest):  # Принимаем JSON
    json_files_names = [file for file in os.listdir('users/') if file.endswith('.json')]
    for json_file_name in json_files_names:
        file_path = os.path.join('users/', json_file_name)
        with open(file_path, 'r') as f:
            json_user = json.load(f)
            user = User(**json_user)
            if user.login == request.login and user.password == request.password:
                # Обновляем токен при авторизации
                user.token = hex(random.getrandbits(128))[2:]
                return {"login": user.login, "token": user.token}
    raise HTTPException(status_code=401, detail="Invalid login or password")

@app.get("/")
def read_root():
    return {"message": "Добро пожаловать!"}

@app.post("/users/")
def user_create(user: User):
    user.id = int(time.time())
    user.token = random.getrandbits(128)

    with open (f"users/user_{user.id}.json","w") as f:
        json.dump(user.model_dump(), f)
    return user

@app.get("/users/{user_id}")
def user_read(user_id: int, q: Union[int, None] = 0, a : Union[int, None] = 0):
    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum}