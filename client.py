import requests
import json
import time
from pydantic import BaseModel
from typing import Union
import hashlib
import re

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

def compute_signature(token: str, body: dict):
    if body is None:
        body_bytes = b""
    else:
        body_bytes = json.dumps(body, separators=(',', ':')).encode()

    if isinstance(token, int):
        token = str(token)

    return hashlib.sha256(token.encode() + body_bytes).hexdigest()

def send_post(endpoint, data, auth_token=None):
    headers = {}
    if auth_token:
        headers["Authorization"] = auth_token
        headers["signature"] = compute_signature(auth_token, data)

    try:
        resp = requests.post(SERVER_URL + endpoint, json=data, headers=headers)
        try:
            j = resp.json()
        except:
            j = None

        if resp.status_code >= 400:
            if j and "detail" in j:
                print(f"Ошибка {resp.status_code}: {j['detail']}")
            else:
                print(f"Ошибка {resp.status_code}: {resp.text}")
            return None

        return j
    except Exception as e:
        print("Ошибка запроса:", e)
        return None


def send_get(endpoint, auth_token=None, params=None):
    headers = {}
    if auth_token:
        headers["Authorization"] = auth_token
        headers["signature"] = compute_signature(auth_token, None)

    try:
        resp = requests.get(SERVER_URL + endpoint, headers=headers, params=params)
        try:
            j = resp.json()
        except:
            j = None

        if resp.status_code >= 400:
            if j and "detail" in j:
                print(f"Ошибка {resp.status_code}: {j['detail']}")
            else:
                print(f"Ошибка {resp.status_code}: {resp.text}")
            return None

        return j
    except Exception as e:
        print("Ошибка запроса:", e)
        return None

def login():
    login = input("Введите login: ")
    password = input("Введите пароль: ")

    res = send_post("/users/auth", {"login": login, "password": password})
    if res:
        print("Авторизация успешна!")
        return {"login": login, "token": res["token"]}
    print("Ошибка авторизации.")
    return None


def register():
    login = input("Введите login: ")
    password = input("Введите пароль: ")
    password_confirmation = input("Подтвердите пароль: ")

    if password != password_confirmation:
        print("Пароли не совпадают.")
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

    res = send_post("/users/", data)
    if res:
        print("Регистрация успешна!")
    else:
        print("Ошибка регистрации.")


def create_user(current_user):
    login = input("Введите login нового пользователя: ")
    password = input("Введите пароль: ")
    password_confirmation = input("Подтвердите пароль: ")

    if password != password_confirmation:
        print("Пароли не совпадают.")
        return

    ok, msg = check_password(password)
    if not ok:
        print("Ошибка:", msg)
        return

    role = input("Роль (или Enter): ") or "basic role"
    token_for_new = "None"

    data = {
        "login": login,
        "password": password,
        "password_confirmation": password_confirmation,
        "role": role,
        "token": token_for_new
    }

    res = send_post("/users/", data, auth_token=current_user["token"])
    if res:
        print("Пользователь создан:", res)
    else:
        print("Ошибка создания пользователя.")


def all_users(current_user):
    user_id = input("Введите ID пользователя: ")

    res = send_get(f"/users/{user_id}", auth_token=current_user["token"], params={"q": 2, "a": 3})
    if res:
        print("Результат:", res)


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

        elif cmd == "exit":
            break

        else:
            print("Неизвестная команда.")

main()