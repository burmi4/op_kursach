from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from typing import Union, Optional
import json
import time
import os
import random
import re
import hashlib
import hmac

app = FastAPI()
USERS_DIR = "users"

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    tech_token: Union[str, int, None] = "None"
    sesion_token: Union[str, int, None] = "None"
    id: Union[int, None] = -1

class LoginRequest(BaseModel):
    login: str
    password: str
    
def verify_request_signature(request: Request,
                                   authorization: str = Header(None),
                                   x_signature: str = Header(None, alias="X-Signature")):
    if not authorization:
        raise HTTPException(status_code=401, detail="Токен не предоставлен (Authorization).")
    path, user_json = find_user_by_session_token(authorization)
    if not path:
        raise HTTPException(status_code=401, detail="Неверный session token.")
    if not x_signature:
        raise HTTPException(status_code=401, detail="Требуется заголовок X-Signature.")

    body_bytes = request.body()  # Читаем сырое тело
    body_str = body_bytes.decode("utf-8") if body_bytes else ""
    body_json = json.loads(body_str) if body_str else None
    body_str_normalized = serialize_body(body_json)

    tech = user_json.get("tech_token")
    if not tech:
        raise HTTPException(status_code=401, detail="У пользователя нет tech_token для проверки подписи.")
    
    msg = (tech + body_str_normalized).encode("utf-8")
    expected_signature = hashlib.sha256(msg).hexdigest()
    
    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(status_code=401, detail="Неверная подпись запроса (X-Signature).")
    return authorization
    
def serialize_body(body: Optional[dict]) -> str:
    if not body:
        return ""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))    

def list_user_files():
    if not os.path.exists(USERS_DIR):
        os.makedirs(USERS_DIR)
    return [os.path.join(USERS_DIR, f) for f in os.listdir(USERS_DIR) if f.endswith(".json")]

def load_user(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_user_login(login: str) -> Optional[str]:
    for path in list_user_files():
        data = load_user(path)
        if data.get("login") == login:
            return path
    return None

def find_user_by_session_token(token: str):
    for path in list_user_files():
        data = load_user(path)
        if data.get("sesion_token") and data.get("sesion_token") == token:
            return path, data
    return None, None

def check_password_rules(password: str):
    if len(password) < 10:
        return False, "Пароль должен быть не менее 10 символов."
    if not re.search(r"[A-Z]", password):
        return False, "В пароле должна быть хотя бы одна заглавная буква."
    if not re.search(r"[a-z]", password):
        return False, "В пароле должна быть хотя бы одна строчная буква."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "В пароле должен быть хотя бы один специальный символ."
    return True, ""

@app.post("/users/")
def user_create(user: User):
    user.id = int(time.time() * 1000)  # более уникальный id
    user.tech_token = hashlib.sha256(str(random.getrandbits(256) + int(time.time())).encode()).hexdigest()
    user.sesion_token = None
    if user.password != user.password_confirmation:
        raise HTTPException(status_code=400, detail="Пароль и подтверждение не совпадают.")
    ok, msg = check_password_rules(user.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    if find_user_login(user.login):
        raise HTTPException(status_code=409, detail="Такой login уже существует.")
    file_path = os.path.join(USERS_DIR, f"user_{user.id}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(user.model_dump(), f, ensure_ascii=False)
    return user

@app.post("/users/auth")
def user_auth(request: LoginRequest):
    for path in list_user_files():
        with open(path, "r", encoding="utf-8") as f:
            json_user = json.load(f)
            if json_user.get("login") == request.login and json_user.get("password") == request.password:
                session_token = hashlib.sha256(str(random.getrandbits(128) + int(time.time())).encode()).hexdigest()
                json_user["sesion_token"] = session_token
                with open(path, "w", encoding="utf-8") as fw:
                    json.dump(json_user, fw, ensure_ascii=False)
                return {"login": json_user.get("login"), "token": session_token, "tech_token": json_user.get("tech_token")}
    raise HTTPException(status_code=401, detail="Неправильный логин или пароль.")

@app.get("/")
def read_root(token: str = Depends(verify_request_signature)):
    return {"message": "Добро пожаловать!"}

@app.get("/users")
def all_users(token: str = Depends(verify_request_signature)):
    data = []
    for path in list_user_files():
        with open(path, "r", encoding="utf-8") as f:
            data.append(json.load(f))
    return data

@app.get("/users/{user_id}")
def user_read(user_id: int, q: Union[int, None] = 0, a : Union[int, None] = 0, token: str = Depends(verify_request_signature)):
    total = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": total}
