from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Union
import json
import time
import os
import random
import re

app = FastAPI()
USERS_DIR = "users"

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

def list_user():
    return [os.path.join(USERS_DIR, f) for f in os.listdir(USERS_DIR) if f.endswith(".json")]

def load_user(path):
    with open(path, "r") as f:
        return json.load(f)

def find_user_login(login: str):
    for path in list_user():
        u = load_user(path)
        if u.get("login") == login:
            return path
    return None
    
def check_password(password: str):
    if len(password) < 10:
        return False, "Пароль должен быть не менее 10 символов."
    if not re.search(r"[A-Z]", password):
        return False, "В пароле должна быть хотя бы одна заглавная буква."
    if not re.search(r"[a-z]", password):
        return False, "В пароле должна быть хотя бы одна строчная буква."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "В пароле должен быть хотя бы один специальный символ."
    return True, ""    

@app.post("/users/auth")
def user_auth(request: LoginRequest):
    json_files_names = [file for file in os.listdir('users/') if file.endswith('.json')]
    for json_file_name in json_files_names:
        file_path = os.path.join('users/', json_file_name)
        with open(file_path, 'r') as f:
            json_user = json.load(f)
            user = User(**json_user)
            if user.login == request.login and user.password == request.password:
                user.token = hex(random.getrandbits(128))[2:]
                return {"login": user.login, "token": user.token}
    raise HTTPException(status_code=401, detail="Неправильный пароль или логин.")

@app.get("/")
def read_root():
    return {"message": "Добро пожаловать!"}

@app.post("/users/")
def user_create(user: User):
    user.id = int(time.time())
    user.token = random.getrandbits(128)
    if user.password != user.password_confirmation:
        raise HTTPException(status_code=400, detail="Пароль и подтверждение не совпадают.")

    ok, msg = check_password(user.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    if find_user_login(user.login):
        raise HTTPException(status_code=409, detail="Такой login уже существует.")

    with open (f"users/user_{user.id}.json","w") as f:
        json.dump(user.model_dump(), f)
    return user

@app.get("/users/{user_id}")
def user_read(user_id: int, q: Union[int, None] = 0, a : Union[int, None] = 0):
    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum}