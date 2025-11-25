from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Union
import json
import time
import os
import random
import hashlib
import re

app = FastAPI()

USERS_DIR = "users"
os.makedirs(USERS_DIR, exist_ok=True)


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

def save_user(data):
    if "id" not in data or not data["id"]:
        data["id"] = int(time.time())
    path = os.path.join(USERS_DIR, f"user_{data['id']}.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def find_user_login(login: str):
    for path in list_user():
        u = load_user(path)
        if u.get("login") == login:
            return path
    return None


def find_user_by_token(token: str):
    for path in list_user():
        u = load_user(path)
        if str(u.get("token")) == str(token):
            return u, path
    return None, None


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


def compute_signature(token: str, body_bytes: bytes) -> str:
    if isinstance(token, int):
        token = str(token)
    if body_bytes is None:
        body_bytes = b""
    return hashlib.sha256(token.encode() + body_bytes).hexdigest()

@app.post("/users/auth")
async def user_auth(request: LoginRequest):
    for path in list_user():
        data = load_user(path)
        if data.get("login") == request.login and data.get("password") == request.password:
            data["token"] = hex(random.getrandbits(128))[2:]
            save_user(data)
            return {"login": data["login"], "token": data["token"]}
    raise HTTPException(status_code=401, detail="Неправильный логин или пароль")


@app.post("/users/")
async def user_create(request: Request, user: User):
    body_bytes = await request.body()

    auth_header = request.headers.get("authorization")
    signature_header = request.headers.get("signature")

    if auth_header:
        expected = compute_signature(auth_header, body_bytes)
        if signature_header != expected:
            raise HTTPException(status_code=401, detail="Отсутствует или неправильная подпись.")
        
        found_user, _ = find_user_by_token(auth_header)
        if not found_user:
            raise HTTPException(status_code=401, detail="Неправильный токен.")

    if user.password != user.password_confirmation:
        raise HTTPException(status_code=400, detail="Пароль и подтверждение не совпадают.")

    ok, msg = check_password(user.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    if find_user_login(user.login):
        raise HTTPException(status_code=409, detail="Такой login уже существует.")

    user.id = int(time.time())

    if not auth_header:
        user.token = hex(random.getrandbits(128))[2:]
    else:
        if not user.token or user.token == "None":
            user.token = hex(random.getrandbits(128))[2:]

    save_user(user.model_dump())

    return user


@app.get("/users/{user_id}")
async def user_read(user_id: int, request: Request, q: int = 0, a: int = 0):
    body_bytes = await request.body()

    auth_header = request.headers.get("authorization")
    signature_header = request.headers.get("signature")

    if not auth_header or not signature_header:
        raise HTTPException(status_code=401, detail="Отсутвует авторизация или подпись")

    expected = compute_signature(auth_header, body_bytes)
    if signature_header != expected:
        raise HTTPException(status_code=401, detail="Неправильная подпись.")

    found_user, _ = find_user_by_token(auth_header)
    if not found_user:
        raise HTTPException(status_code=401, detail="Неправильный токен.")

    return {"user_id": user_id, "q": q, "a": a, "sum": q + a}
