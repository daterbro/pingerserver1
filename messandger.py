from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import bcrypt
import jwt
import sqlite3
from typing import Union
import uvicorn
import json

# Конфигурации
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Создание базы данных SQLite
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

# Функция для обновления структуры базы данных
def update_database():
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'last_token_update' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_token_update DATETIME")
        conn.commit()

        cursor.execute("UPDATE users SET last_token_update = CURRENT_TIMESTAMP")
        conn.commit()

        print("Столбец 'last_token_update' добавлен в таблицу 'users'.")

# Обновляем структуру базы данных
update_database()

# Создание таблиц, если они не существуют
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY, 
    password TEXT, 
    last_token_update DATETIME DEFAULT CURRENT_TIMESTAMP
)''')
cursor.execute(
    '''CREATE TABLE IF NOT EXISTS user_settings (user_id INTEGER PRIMARY KEY, username TEXT UNIQUE, language TEXT, avatar TEXT)''')
# Создание таблицы для хранения чатов
cursor.execute('''CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY, user_id INTEGER, chat_with TEXT)''')
conn.commit()
# Создание таблицы для хранения сообщений
cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    sender INTEGER, 
    receiver TEXT, 
    text TEXT, 
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')
conn.commit()



app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app.mount("/static", StaticFiles(directory="static"), name="static")


templates = Jinja2Templates(directory="static")


class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserSettings(BaseModel):
    username: str
    language: str
    avatar: str

class ChatCreate(BaseModel):
    user_id: int
    chat_with: str


def create_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    cursor.execute("UPDATE users SET last_token_update = ? WHERE email = ?", (datetime.utcnow(), data["sub"]))
    conn.commit()

    return encoded_jwt

# Функция для декодирования JWT токена
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.post("/register")
def register(user: UserLogin):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (user.email, hashed_password))
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"message": "User registered successfully", "user_id": user_id}


@app.post("/login")
def login(user: UserLogin):
    cursor.execute("SELECT rowid, password FROM users WHERE email = ?", (user.email,))
    result = cursor.fetchone()
    if result and bcrypt.checkpw(user.password.encode('utf-8'), result[1]):
        user_id = result[0]
        token = create_token(data={"sub": user.email, "user_id": user_id})
        return {"token": token, "user_id": user_id}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/chats/{user_id}")
def get_chats(user_id: int):
    print(f"Запрос на получение чатов для user_id: {user_id}")
    try:
        cursor.execute(""" 
            SELECT chats.chat_with, us.avatar 
            FROM chats 
            JOIN user_settings us ON chats.chat_with = us.username 
            WHERE chats.user_id = ? 
        """, (user_id,))
        chats = cursor.fetchall()
        print(f"Найденные чаты: очень много текста")


        return {
            "chats": [
                {"username": chat[0], "avatar": chat[1]} for chat in chats
            ]
        }
    except Exception as e:
        print(f"Ошибка при получении чатов: {str(e)}")
        return {"chats": []}


# Создание нового чата
@app.post("/chats/")
def create_chat(chat: ChatCreate):
    try:

        cursor.execute("SELECT * FROM chats WHERE user_id = ? AND chat_with = ?", (chat.user_id, chat.chat_with))
        existing_chat = cursor.fetchone()
        if existing_chat:
            raise HTTPException(status_code=400, detail="Chat already exists.")

        print(f"Создание чата с user_id: {chat.user_id}, chat_with: {chat.chat_with}")
        cursor.execute("INSERT INTO chats (user_id, chat_with) VALUES (?, ?)", (chat.user_id, chat.chat_with))
        conn.commit()


        cursor.execute("SELECT avatar FROM user_settings WHERE username = ?", (chat.chat_with,))
        avatar = cursor.fetchone()

        return {
            "message": "Chat created successfully",
            "chat_id": cursor.lastrowid,
            "avatar": avatar[0] if avatar else None
        }
    except Exception as e:
        print(f"Ошибка при создании чата: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error creating chat: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def get(request: Request):
    return templates.TemplateResponse("oform.html", {"request": request})


@app.get("/profile")
def get_profile(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None or "user_id" not in payload:
        return JSONResponse({"status": "error", "message": "Not authenticated"}, status_code=401)

    user_id = payload["user_id"]

    # Проверка времени последнего обновления токена
    cursor.execute("SELECT last_token_update FROM users WHERE rowid = ?", (user_id,))
    last_update = cursor.fetchone()
    if last_update:
        last_update_time = datetime.fromisoformat(last_update[0])
        if datetime.utcnow() - last_update_time > timedelta(days=30):
            return JSONResponse({"status": "error", "message": "Token expired. Please log in again."}, status_code=401)

    user_profile = load_user_profile(user_id)
    return JSONResponse({"status": "success", "data": user_profile})


def load_user_profile(user_id: int):
    cursor.execute("SELECT email FROM users WHERE rowid = ?", (user_id,))
    result = cursor.fetchone()
    if result:
        return {"user_id": user_id, "email": result[0]}
    return None


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            data = await websocket.receive_text()
            data = json.loads(data)

            # Обработка команд регистрации и входа
            if data["command"] == "register":
                await handle_register(data, websocket)

            elif data["command"] == "login":
                await handle_login(data, websocket)

            elif data["command"] == "saveSettings":
                user_id = data["user_id"]
                settings = data["settings"]
                save_user_settings(user_id, settings)
                await websocket.send_text(json.dumps({"status": "success", "command": "settingsSaved"}))

            elif data["command"] == "loadSettings":
                user_id = data["user_id"]
                settings = load_user_settings(user_id)
                await websocket.send_text(json.dumps({
                    "username": settings.username,
                    "language": settings.language,
                    "avatar": settings.avatar
                }))

            elif data["command"] == "checkUsername":
                username = data["username"]
                await check_username(username, websocket)

            elif data["command"] == "searchUser":
                tag = data["tag"]
                await search_user(tag, websocket)

            elif data["command"] == "startChat":
                user = data["user"]
                user_id = data["user_id"]
                await start_chat(user, websocket, user_id)

            elif data["command"] == "getChats":
                user_id = data["user_id"]
                chats = get_chats(user_id)
                await websocket.send_text(
                    json.dumps({"status": "success", "command": "chatList", "chats": chats["chats"]}))


            elif data["command"] == "getusername":
                user_id = data["user_id"]

                # Запрос на получение username по user_id
                cursor.execute("SELECT username FROM user_settings WHERE user_id = ?", (user_id,))
                result = cursor.fetchone()

                if result:
                    # Если найден username, отправляем его обратно клиенту
                    await websocket.send_text(json.dumps({
                        "status": "success",
                        "command": "username",
                        "user_id": user_id,
                        "username": result[0]
                    }))
                    print("отправка юзернейма")
                else:
                    # Если username не найден
                    await websocket.send_text(json.dumps({
                        "status": "error",
                        "command": "username",
                        "message": "User not found"
                    }))
                    print("Ошибка")



            elif data["command"] == "sendMessage":
                sender = data["user_id"]
                receiver = data["receiver"]
                text = data["text"]

                cursor.execute("INSERT INTO messages (sender, receiver, text) VALUES (?, ?, ?)", (sender, receiver, text))
                conn.commit()


                await websocket.send_text(json.dumps({
                    "status": "success",
                    "command": "messageSent",
                    "message": text
                }))




            # Получаем сообщения между пользователями

            elif data["command"] == "getMessages":
                chat_with = data["chatWith"]
                user_id = data["user_id"]

                print(f"Получение сообщений для user_id: {user_id}, chat_with: {chat_with}")

                # Выполняем запрос к базе данных без JOIN
                cursor.execute("""
                    SELECT m.sender, m.text, m.timestamp, m.receiver
                    FROM messages m
                    WHERE (m.sender = ? AND m.receiver = ?) OR (m.sender = ? AND m.receiver = ?)
                    ORDER BY m.timestamp
                """, (user_id, chat_with, chat_with, user_id))

                messages = cursor.fetchall()

                print(f"Отправляем сообщения: {messages}")

                # Отправляем сообщения обратно через WebSocket
                await websocket.send_text(json.dumps({
                    "status": "success",
                    "command": "messages",
                    "messages": [
                        {"sender": msg[0], "receiver": msg[3], "text": msg[1], "timestamp": msg[2]} for msg in messages
                    ]
                }))





        except WebSocketDisconnect:
            break
        except Exception as e:
            await websocket.send_text(json.dumps({"status": "error", "message": str(e)}))



async def handle_register(data, websocket):
    email = data["email"]
    password = data["password"]
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        user_id = cursor.lastrowid
        await websocket.send_text(json.dumps({
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id
        }))
    except sqlite3.IntegrityError:
        await websocket.send_text(json.dumps({"status": "error", "message": "User already exists"}))


async def handle_login(data, websocket):
    email = data["email"]
    password = data["password"]
    cursor.execute("SELECT rowid, password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[1]):
        user_id = result[0]

        # Получаем имя пользователя
        cursor.execute("SELECT username FROM user_settings WHERE user_id = ?", (user_id,))
        username_result = cursor.fetchone()
        username = username_result[0] if username_result else None

        token = create_token(data={"sub": email, "user_id": user_id})  # Включаем user_id в токен
        await websocket.send_text(json.dumps({
            "status": "success",
            "token": token,
            "user_id": user_id,
            "username": username,  # Отправляем имя пользователя
            "message": "Login successful"
        }))
    else:
        await websocket.send_text(json.dumps({"status": "error", "message": "Invalid credentials"}))


# Функция для проверки существования юзернейма
async def check_username(username: str, websocket: WebSocket):
    cursor.execute("SELECT user_id FROM user_settings WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        # Юзернейм существует
        await websocket.send_text(json.dumps({"status": "success", "command": "usernameExists", "username": username}))
    else:
        # Юзернейм не существует
        await websocket.send_text(json.dumps({"status": "success", "command": "usernameNotFound"}))

# Функция для сохранения настроек пользователя
def save_user_settings(user_id: int, settings: dict):
    cursor.execute(""" 
        INSERT INTO user_settings (user_id, username, language, avatar) 
        VALUES (?, ?, ?, ?) 
        ON CONFLICT(user_id) DO UPDATE SET 
        username=excluded.username, 
        language=excluded.language, 
        avatar=excluded.avatar; 
    """, (user_id, settings['username'], settings['language'], settings['avatar']))
    conn.commit()

# Функция для загрузки настроек пользователя
def load_user_settings(user_id: int):
    cursor.execute("SELECT username, language, avatar FROM user_settings WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    if result:
        return UserSettings(username=result[0], language=result[1], avatar=result[2])
    else:
        return UserSettings(username="", language="en", avatar="")  # Значения по умолчанию

# Функция для поиска пользователей по тегу
async def search_user(tag: str, websocket: WebSocket):
    tag = tag.strip()  # Удалить лишние пробелы
    if not tag.startswith('@'):
        await websocket.send_text(json.dumps({"status": "error", "message": "Tag must start with '@'."}))
        return

    cursor.execute("SELECT username, avatar FROM user_settings WHERE username LIKE ? LIMIT 4", ('%' + tag[1:] + '%',))
    results = cursor.fetchall()

    # Создаем список с именами пользователей и их аватарками
    users = [{"username": row[0], "avatar": row[1]} for row in results]

    await websocket.send_text(json.dumps({
        "status": "success",
        "command": "searchResult",
        "users": users
    }))

# Функция для начала чата
async def start_chat(user: str, websocket: WebSocket, user_id: str):
    # Сохраняем или получаем чат
    cursor.execute("SELECT * FROM chats WHERE user_id = ? AND chat_with = ?", (user_id, user))
    chat = cursor.fetchone()
    if not chat:
        cursor.execute("INSERT INTO chats (user_id, chat_with) VALUES (?, ?)", (user_id, user))
        conn.commit()

    # Отправляем сообщение о начале чата
    await websocket.send_text(json.dumps({"status": "success", "command": "chatStarted", "user": user}))



# Запуск приложения
if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8080)
