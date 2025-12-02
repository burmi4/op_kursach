import requests
import json
import time
from pydantic import BaseModel
from typing import Union
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

def send_post(endpoint, data, headers=None):
    try:
        response = requests.post(f"{SERVER_URL}{endpoint}", json=data, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {e}")
        return None

def send_get(endpoint, headers=None):
    try:
        response = requests.get(f"{SERVER_URL}{endpoint}", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {e}")
        return None

def login():
    login_input = input("Введите login (или 'exit' для выхода): ").strip()
    if login_input == "exit":
        return None
    password_input = input("Введите password: ").strip()
    
    data = {"login": login_input, "password": password_input}
    result = send_post("/users/auth", data)
    if result and "token" in result:
        print(f"Авторизация успешна! Login: {login_input}, Токен: {result['token']}")
        return {"login": login_input, "token": result["token"]}
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
    result = send_post("/users/", data)
    if result:
        print(f"Регистрация успешна! ID: {result.get('id')}. Теперь авторизуйтесь.")
    else:
        print("Ошибка регистрации.")

def authenticated_menu(token):
    while True:
        print("\nАвторизованные команды:")
        print("1 - Получить всех пользователей (/users)")
        print("2 - Получить пользователя по ID (/users/{id})")
        print("exit - выход в главное меню")

        cmd = input("> ")

        headers = {"Authorization": token}

        if cmd == "1":
            result = send_get("/users", headers=headers)
            if result:
                print("Все пользователи:", json.dumps(result, indent=2))
            else:
                print("Ошибка доступа.")

        elif cmd == "2":
            user_id = input("Введите user_id: ")
            result = send_get(f"/users/{user_id}", headers=headers)
            if result:
                print("Пользователь:", json.dumps(result, indent=2))
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
                authenticated_menu(current["token"])

        elif cmd == "exit":
            break

        else:
            print("Неизвестная команда.")

main()