import requests
import json
import time
from pydantic import BaseModel
from typing import Union

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    token: Union[str, int, None] = "None"
    id: Union[int, None] = -1

SERVER_URL = "http://127.0.0.1:8000"

def send_post(endpoint, data):
    try:
        response = requests.post(f"{SERVER_URL}{endpoint}", json=data)
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

def create_user(current_user):
    login = input("Введите login: ")
    password = input("Введите password: ")
    password_confirmation = input("Подтвердите password: ")
    if password != password_confirmation:
        print("Пароли не совпадают!")
        return
    role = input("Введите role (по умолчанию 'basic role'): ") or "basic role"
    token = input("Введите token (по умолчанию 'None'): ") or "None"
    
    data = {
        "login": login,
        "password": password,
        "password_confirmation": password_confirmation,
        "role": role,
        "token": token
    }
    headers = {"Authorization": f"{current_user['token']}"}
    try:
        response = requests.post(f"{SERVER_URL}/users/", json=data, headers=headers)
        response.raise_for_status()
        result = response.json()
        print(f"Пользователь создан с ID: {result.get('id')}")
    except requests.exceptions.RequestException as e:
        print(f"Ошибка: {e}. Возможно, доступ запрещён.")

def all_users(current_user):
    headers = {"Authorization": f"{current_user['token']}"}
    try:
        response = requests.get(f"{SERVER_URL}/users/", headers=headers)
        response.raise_for_status()
        result = response.json()
        if isinstance(result, list):
            for user_data in result:
                user = User(**user_data)
                print(f"ID: {user.id}, Login: {user.login}, Role: {user.role}")
        else:
            print("Ошибка получения списка.")
    except requests.exceptions.RequestException as e:
        print(f"Ошибка: {e}. Возможно, доступ запрещён.")

def main():
    current_user = None
    while True:
        print("\nДоступные команды:")
        print("1 - Создать пользователя")
        print("2 - Просмотреть всех пользователей")
        print("3 - Регистрация")
        print("4 - Авторизация")
        print("exit - Полный выход")
        command = input("Введите команду: ").strip()
        
        if command == "1":
            if not current_user:
                print("Сначала авторизуйтесь.")
            else:
                create_user(current_user)
        elif command == "2":
            if not current_user:
                print("Сначала авторизуйтесь.")
            else:
                all_users(current_user)
        elif command == "3":
            register()
        elif command == "4":
            current_user = login()
            if not current_user:
                print("Авторизация отменена.")
        elif command == "exit":
            break
        else:
            print("Неизвестная команда.")

main()