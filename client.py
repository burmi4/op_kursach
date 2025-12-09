import requests
import json
import time
import hmac
import hashlib
from pydantic import BaseModel
from typing import Union, Optional
import re
import os
from typing import Dict

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    token: Union[str, int, None] = "None"
    id: Union[int, None] = -1

SERVER_URL = "http://127.0.0.1:8000"

def check_password(password: str):
    if len(password) < 10:
        return False, "Пароль должен быть не менее 10 символов."
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать заглавную букву."
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать строчную букву."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Пароль должен содержать спецсимвол."
    return True, ""

def serialize_body(body: Optional[dict]) -> str:
    if not body:
        return ""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sig_plain_token(token: str) -> Dict[str, str]:
    return {"Authorization": token}

def sig_token_plus_time(token: str, ts: Optional[int] = None) -> Dict[str, str]:
    if ts is None:
        ts = int(time.time())
    msg = f"{token}{ts}".encode("utf-8")
    signature = hashlib.sha256(msg).hexdigest()
    return {"Authorization": signature}

def sig_token_plus_body(token: str, body: Optional[dict]) -> Dict[str, str]:
    body_str = serialize_body(body)
    msg = (token + body_str).encode("utf-8")
    signature = hashlib.sha256(msg).hexdigest()
    return {"Authorization": signature}

def sig_token_body_and_time(token: str, body: Optional[dict], ts: Optional[int] = None) -> Dict[str, str]:
    if ts is None:
        ts = int(time.time())
    body_str = serialize_body(body)
    msg = (token + body_str + str(ts)).encode("utf-8")
    signature = hashlib.sha256(msg).hexdigest()
    return {"Authorization": signature}

def build_signature_headers(method: str, endpoint: str, body: Optional[dict], tech_token: str):
    body_json = serialize_body(body)
    message = f"{method}\n{endpoint}\n{body_json}"
    signature = hmac.new(tech_token.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {"X-Signature": signature}

def send_post(endpoint, data, session_token=None, tech_token=None, extra_headers=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = extra_headers.copy() if extra_headers else {}
    if session_token:
        headers["Authorization"] = session_token
    if tech_token and session_token:
        sig_headers = sig_token_plus_body(tech_token, data)
        headers["X-Signature"] = sig_headers["Authorization"]
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {e}")
        try:
            print("Response text:", response.text)
        except:
            pass
        return None

def send_get(endpoint, session_token=None, tech_token=None, extra_headers=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = extra_headers.copy() if extra_headers else {}
    if session_token:
        headers["Authorization"] = session_token
    if tech_token and session_token:
        sig_headers = sig_token_plus_body(tech_token, {})
        headers["X-Signature"] = sig_headers["Authorization"]
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {e}")
        try:
            print("Response text:", response.text)
        except:
            pass
        return None

def login():
    login_input = input("Введите login (или 'exit' для выхода): ").strip()
    if login_input == "exit":
        return None
    password_input = input("Введите password: ").strip()
    data = {"login": login_input, "password": password_input}
    result = send_post("/users/auth", data)  # логин/пароль не подписываем
    if result and "token" in result:
        print(f"Авторизация успешна! Login: {login_input}, Сессионный токен: {result['token']}")
        tech = result.get("tech_token")
        if tech:
            print("Получен tech_token (секрет для подписи запросов).")
        return {"login": login_input, "token": result["token"], "tech_token": tech}
    else:
        print("Неверный login или password.")
        return None

def register():
    login = input("Введите login: ")
    password = input("Введите password: ")
    password_confirmation = input("Подтвердите password: ")
    if password != password_confirmation:
        print("Пароли не совпадают!")
        return
    ok, msg = check_password(password)
    if not ok:
        print("Ошибка:", msg)
        return
    data = {
        "login": login,
        "password": password,
        "password_confirmation": password_confirmation,
        "role": "basic role",
        "token": "None"
    }
    result = send_post("/users/", data)  # регистрация без подписи
    if result:
        print(f"Регистрация успешна! ID: {result.get('id')}. Теперь авторизуйтесь.")
    else:
        print("Ошибка регистрации.")

def authenticated_menu(session_token, tech_token):
    while True:
        print("\nАвторизованные команды:")
        print("1 - Получить всех пользователей (/users)")
        print("2 - Получить пользователя по ID (/users/{id})")
        print("exit - выход в главное меню")

        cmd = input("> ")

        if cmd == "1":
            result = send_get("/users", session_token=session_token, tech_token=tech_token)
            if result:
                print("Все пользователи:", json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print("Ошибка доступа.")

        elif cmd == "2":
            user_id = input("Введите user_id: ")
            result = send_get(f"/users/{user_id}", session_token=session_token, tech_token=tech_token)
            if result:
                print("Пользователь:", json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print("Ошибка доступа.")
        elif cmd == "exit":
            break
        else:
            print("Неизвестная команда.")

def main():
    current = None
    while True:
        print("\nКоманды:")
        print("1 - Регистрация")
        print("2 - Авторизация")
        print("exit - выход")

        cmd = input("> ")

        if cmd == "1":
            register()
        elif cmd == "2":
            current = login()
            if current:
                authenticated_menu(current["token"], current.get("tech_token"))
        elif cmd == "exit":
            break
        else:
            print("Неизвестная команда.")
main()
