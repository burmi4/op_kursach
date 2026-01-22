import requests
import json
import time
import hmac
import hashlib
from pydantic import BaseModel
from typing import Union, Optional
import re

SERVER_URL = "http://127.0.0.1:8000"

class User(BaseModel):
    login: str
    password: str
    password_confirmation: str
    role: Union[str, None] = "basic role"
    token: Union[str, int, None] = "None"
    id: Union[int, None] = -1

def print_response_error(response):
    try:
        error_json = response.json()
        if "detail" in error_json:
            detail = error_json["detail"]
            if isinstance(detail, list):
                print("Ошибки валидации данных:")
                for item in detail:
                    msg = item.get("msg", "Ошибка")
                    loc = item.get("loc", [])
                    print(f"- {msg} (поле: {loc[-1] if loc else '?'})")
            else:
                print(f"Ошибка: {detail}")
        else:
            print(f"Ошибка (ответ сервера): {response.text}")
    except requests.exceptions.JSONDecodeError:
        print(f"Сырой ответ сервера: {response.text}")

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

def serialize_body(body: Optional[dict]):
    if not body:
        return ""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",",":"))

def sig_token_plus_body(token: str, body: Optional[dict]):
    body_str = serialize_body(body)
    msg = (token + body_str).encode("utf-8")
    signature = hashlib.sha256(msg).hexdigest()
    return {"Authorization": signature}

def send_post(endpoint, data=None, session_token=None, tech_token=None, extra_headers=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = extra_headers.copy() if extra_headers else {}
    if session_token:
        headers["Authorization"] = session_token
    if tech_token and session_token:
        sig_headers = sig_token_plus_body(tech_token, data)
        headers["X-Signature"] = sig_headers["Authorization"]
    try:
        response = requests.post(url, json=data, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")
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
        return response
    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")
        return None

def send_delete(endpoint, session_token=None, tech_token=None, extra_headers=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = extra_headers.copy() if extra_headers else {}
    if session_token:
        headers["Authorization"] = session_token
    if tech_token and session_token:
        sig_headers = sig_token_plus_body(tech_token, {})
        headers["X-Signature"] = sig_headers["Authorization"]
    try:
        response = requests.delete(url, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")
        return None

def send_patch(endpoint, data=None, session_token=None, tech_token=None, extra_headers=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = extra_headers.copy() if extra_headers else {}
    if session_token:
        headers["Authorization"] = session_token
    if tech_token and session_token:
        sig_headers = sig_token_plus_body(tech_token, data)
        headers["X-Signature"] = sig_headers["Authorization"]
    try:
        response = requests.patch(url, json=data, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")
        return None

def login():
    login_input = input("Введите login (или 'exit' для выхода): ").strip()
    if login_input == "exit":
        return None
    password_input = input("Введите password: ").strip()
    data = {"login": login_input, "password": password_input}
    
    response = send_post("/users/auth", data)
    if response is not None and response.status_code == 200:
        result = response.json()
        if "token" in result:
            print(f"Авторизация успешна! Login: {login_input}")
            tech = result.get("tech_token")
            return {"login": login_input, "token": result["token"], "tech_token": tech}
        else:
            print("Неверный login или password.")
    elif response is not None:
        print_response_error(response)
    
    return None

def register():
    login = input("Введите login: ")
    password = input("Введите password (необходимы: 10+ символов, спецсимвол, заглавные буква): ")
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
    
    response = send_post("/users/", data)
    if response is not None and response.status_code == 200:
        result = response.json()
        print(f"Регистрация успешна! ID: {result.get('id')}. Tech token: {result.get('tech_token')}.")
    elif response is not None:
        print_response_error(response)

def authenticated_menu(session_token, tech_token):
    while True:
        print("\nАвторизованные команды:")
        print("1 - Получить числа запаздывающего генератора Фибоначчи в диапазоне [a, b]")
        print("2 - Получить визуализацию генератора Фибоначчи до N")
        print("3 - Получить историю запросов")
        print("4 - Удалить историю запросов")
        print("5 - Изменить пароль")
        print("exit - выход в главное меню")

        try:
            cmd = input("> ")

            if cmd == "1":
                try:
                    a = int(input("Введите a: "))
                    b = int(input("Введите b: "))
                    data = {"a": a, "b": b}
                    response = send_post("/fibrange", data, session_token=session_token, tech_token=tech_token)
                    
                    if response is not None and response.status_code == 200:
                        print(f"Числа из диапазона [{a}, {b}]:", response.json().get("values"))
                    elif response is not None:
                        print_response_error(response)
                except ValueError:
                    print("Ошибка: Введите корректные числа.")

            elif cmd == "2":
                try:
                    n = int(input("Введите N: "))
                    format_ = input("Введите формат (link, base64, binary, text): ").strip()
                    data = {"n": n, "format": format_}
                    response = send_post("/fibvis", data, session_token=session_token, tech_token=tech_token)
                    
                    if response is not None and response.status_code == 200:
                        if format_ == "binary":
                            filename = "fibvis.png"
                            with open(filename, "wb") as f:
                                f.write(response.content)
                            print(f"Изображение сохранено в {filename}")
                        else:
                            js = response.json()
                            if format_ == "link":
                                print("Ссылка:", js["link"])
                            elif format_ == "base64":
                                print("Base64:", js["base64"]) 
                            elif format_ == "text":
                                print("Текст:\n", js["text"])
                    elif response is not None:
                        print_response_error(response)
                except ValueError:
                     print("Ошибка: N должно быть числом.")

            elif cmd == "3":
                response = send_get("/history", session_token=session_token, tech_token=tech_token)
                if response is not None and response.status_code == 200:
                    print("История запросов:", json.dumps(response.json(), indent=2, ensure_ascii=False))
                elif response is not None:
                    print_response_error(response)

            elif cmd == "4":
                response = send_delete("/history", session_token=session_token, tech_token=tech_token)
                if response is not None and response.status_code == 200:
                    print(response.json()["message"])
                elif response is not None:
                    print_response_error(response)

            elif cmd == "5":
                new_password = input("Введите новый password: ")
                password_confirmation = input("Подтвердите password: ")
                data = {"new_password": new_password, "password_confirmation": password_confirmation}
                response = send_patch("/users/password", data, session_token=session_token, tech_token=tech_token)
                
                if response is not None and response.status_code == 200:
                    js = response.json()
                    print(js["message"])
                    print("Технический токен изменен. Пожалуйста, авторизуйтесь заново.")
                    break
                elif response is not None:
                    print_response_error(response)

            elif cmd == "exit":
                break
            else:
                print("Неизвестная команда.")
        except Exception as X:
            print(f"Произошла ошибка: {X}")


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