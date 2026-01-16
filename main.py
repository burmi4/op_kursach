import random
import matplotlib
matplotlib.use("Agg")
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from typing import Union, Optional, List
import json
import time
import os
import random
import re
import hashlib
import hmac
import matplotlib.pyplot as plt
import numpy as np
from io import BytesIO
import base64
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles


app = FastAPI()

app.mount("/images", StaticFiles(directory="images"), name="images")

USERS_DIR = "users"
SERVER_URL = "http://127.0.0.1:8000"

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    tech_token: Union[str, int, None] = "None"
    sesion_token: Union[str, int, None] = "None"
    id: Union[int, None] = -1
    history: List[dict] = []

class LoginRequest(BaseModel):
    login: str
    password: str

async def verify_request_signature(request: Request,
                                   authorization: str = Header(None),
                                   x_signature: str = Header(None, alias="X-Signature")):
    if not authorization:
        raise HTTPException(status_code=401, detail="Токен не предоставлен.")
    path, user_json = find_user_by_session_token(authorization)
    if not path:
        raise HTTPException(status_code=401, detail="Неверный токен.")
    if not x_signature:
        raise HTTPException(status_code=401, detail="Требуется заголовок X-Signature.")

    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8") if body_bytes else ""
    body_json = json.loads(body_str) if body_str else None
    body_str_normalized = serialize_body(body_json)

    tech = user_json.get("tech_token")
    if not tech:
        raise HTTPException(status_code=401, detail="У пользователя нет tech_token для проверки подписи.")
    
    msg = (tech + body_str_normalized).encode("utf-8")
    expected_signature = hashlib.sha256(msg).hexdigest()
    
    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(status_code=401, detail="Неверная подпись запроса.")
    
    if request.url.path != "/history":
        user_json["history"] = user_json.get("history", [])
        user_json["history"].append({
            "method": request.method,
            "endpoint": request.url.path,
            "body": body_json,
            "time": time.time()
        })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(user_json, f, ensure_ascii=False)
    
    return authorization

def serialize_body(body: Optional[dict]):
    if not body:
        return ""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def list_user_files():
    if not os.path.exists(USERS_DIR):
        os.makedirs(USERS_DIR)
    return [os.path.join(USERS_DIR, f) for f in os.listdir(USERS_DIR) if f.endswith(".json")]

def load_user(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_user_login(login: str):
    for path in list_user_files():
        data = load_user(path)
        if data.get("login") == login:
            return path
    return None

def find_user_by_session_token(token):
    for path in list_user_files():
        data = load_user(path)
        if data.get("sesion_token") and data.get("sesion_token") == token:
            return path, data
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

def fibonacci_sequence(n):
    a = 24
    b = 55
    m = 2**32
    
    if n <= 0:
        return []
    
    sequence = [random.getrandbits(30) for i in range(b)]
    
    if n > b:
        for i in range(b, n):
            new_val = (sequence[i - a] + sequence[i - b]) % m
            sequence.append(new_val)
            
    return sequence[:n]

def generate_fib_image(seq, n):
    plt.figure(figsize=(10, 6))
    plt.style.use("seaborn-v0_8-whitegrid")
    x = np.arange(1, len(seq) + 1)
    y = np.array(seq)
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.scatter(x, y, c=y, cmap='viridis', s=150, edgecolors='black', zorder=3)
    for xi, yi in zip(x, y):
        ax.text(xi, yi + (max(y)*0.02), f"{yi}", ha="center", fontsize=9)
    ax.axis('off') 
    buf = BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight") 
    plt.close(fig)
    return buf.getvalue()

def generate_fib_text(seq):
    s = "Запаздывающий генератор Фибоначчи:\n"
    for i, val in enumerate(seq):
        s += f"{i+1}: {val}\n"
    return s

def is_prime(num):
    if num < 2:
        return False
    if num == 2:
        return True
    if num % 2 == 0:
        return False
    i = 3
    while i * i <= num:
        if num % i == 0:
            return False
        i += 2
    return True

def generate_primes(n):
    if n <= 0:
        return []

    fib_numbers = fibonacci_sequence(n * 20)

    primes = []
    seen = set()

    for value in fib_numbers:
        ogr = abs(value) % 10_000 + 2
        if ogr not in seen and is_prime(ogr):
            primes.append(ogr)
            seen.add(ogr)
            if len(primes) == n:
                break

    return primes

@app.post("/users/")
def user_create(user: User):
    user.id = int(time.time() * 1000)
    user.tech_token = hashlib.sha256(str(random.getrandbits(256) + int(time.time())).encode()).hexdigest()
    user.sesion_token = None
    user.history = []
    if user.password != user.password_confirmation:
        raise HTTPException(status_code=400, detail="Пароль и подтверждение не совпадают.")
    ok, msg = check_password(user.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    if find_user_login(user.login):
        raise HTTPException(status_code=409, detail="Такой логин уже существует.")
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
def user_read(user_id: int, q: Union[int, None] = 0, a: Union[int, None] = 0, token: str = Depends(verify_request_signature)):
    total = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": total}

@app.get("/history")
def get_history(token: str = Depends(verify_request_signature)):
    path, user = find_user_by_session_token(token)
    return user.get("history", [])

@app.delete("/history")
def delete_history(token: str = Depends(verify_request_signature)):
    path, user = find_user_by_session_token(token)
    user["history"] = []
    with open(path, "w", encoding="utf-8") as f:
        json.dump(user, f, ensure_ascii=False)
    return {"message": "History deleted"}

@app.patch("/users/password")
def change_password(body: dict, token: str = Depends(verify_request_signature)):
    if "new_password" not in body or "password_confirmation" not in body:
        raise HTTPException(status_code=400, detail="Обязательные поля: new_password и password_confirmation")
    new_password = body["new_password"]
    password_confirmation = body["password_confirmation"]
    if new_password != password_confirmation:
        raise HTTPException(status_code=400, detail="Пароль не совпадает")
    ok, msg = check_password(new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    path, user = find_user_by_session_token(token)
    user["password"] = new_password
    new_tech = hashlib.sha256(str(random.getrandbits(256) + int(time.time())).encode()).hexdigest()
    user["tech_token"] = new_tech
    with open(path, "w", encoding="utf-8") as f:
        json.dump(user, f, ensure_ascii=False)
    return {"message": "Password changed", "new_tech_token": new_tech}

@app.post("/primes")
def get_primes(body: dict, token: str = Depends(verify_request_signature)):
    if "n" not in body:
        raise HTTPException(status_code=400, detail="n обязательно")

    if not isinstance(body["n"], int) or body["n"] <= 0:
        raise HTTPException(status_code=400, detail="n должно быть положительным целым числом")

    primes = generate_primes(body["n"])
    return {"primes": primes}


@app.post("/fibvis")
def get_fibvis(body: dict, request: Request, token: str = Depends(verify_request_signature)):
    if "n" not in body or "format" not in body:
        raise HTTPException(status_code=400, detail="Обязательные поля: n и format")
    n = body["n"]
    format_ = body["format"]
    if not isinstance(n, int) or n <= 0:
        raise HTTPException(status_code=400, detail="n должно быть положительным целым числом")
    if format_ not in ["link", "base64", "binary", "text"]:
        raise HTTPException(status_code=400, detail="Invalid format")
    seq = fibonacci_sequence(n)
    
    if format_ == "text":
        text = generate_fib_text(seq)
        return {"text": text}
    
    img_bytes = generate_fib_image(seq, n)
    
    if format_ == "base64":
        b64 = base64.b64encode(img_bytes).decode()
        return {"base64": b64}
    elif format_ == "binary":
        return Response(content=img_bytes, media_type="image/png")
    elif format_ == "link":
        path, user = find_user_by_session_token(token)
        user_id = user["id"]
        filename = f"fib_{user_id}_{int(time.time())}.png"
        file_path = os.path.join("images", filename)
        with open(file_path, "wb") as f:
            f.write(img_bytes)
        link = f"{SERVER_URL}/images/{filename}"
        return {"link": link}