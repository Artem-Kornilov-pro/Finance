import os
import psycopg2
from psycopg2 import pool, extras
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
from pydantic.types import condecimal
from typing import List
import redis
import jwt
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import uvicorn
# Загрузка переменных окружения
load_dotenv()

# Настройки
POSTGRES_USERNAME = os.getenv("POSTGRES_USERNAME")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST")
POSTGRES_PORT = os.getenv("POSTGRES_PORT")
POSTGRES_DATABASE = os.getenv("POSTGRES_DATABASE")
SECRET_KEY = os.getenv("RANDOM_SECRET")
TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = f"postgresql://{POSTGRES_USERNAME}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}"

# Настройка БД
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
db_pool = pool.SimpleConnectionPool(1, 10, DATABASE_URL)

def get_connection():
    return db_pool.getconn()

def release_connection(conn):
    db_pool.putconn(conn)

def create_tables():
    queries = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            type VARCHAR(10) CHECK (type IN ('income', 'expense')) NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount DECIMAL(10,2) NOT NULL,
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            type VARCHAR(10) CHECK (type IN ('income', 'expense')) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for query in queries:
                cursor.execute(query)
        conn.commit()
    finally:
        release_connection(conn)



# Инициализация API
app = FastAPI()

# Модели данных
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    email: EmailStr
    password: str

class TransactionCreate(BaseModel):
    user_id: int
    amount: condecimal(max_digits=10, decimal_places=2)
    category_id: int
    type: str

class TransactionUpdate(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)
    category_id: int
    type: str


class CategoryCreate(BaseModel):
    user_id: int
    name: str
    type: str

# Функции для работы с токенами
def create_token(user_id: int):
    payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    redis_client.setex(f"token:{user_id}", TOKEN_EXPIRE_MINUTES * 60, token)
    return token

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")



@app.get("/ping")
def ping():
    return {"message": "pong"}

# Эндпойнты пользователей
@app.post("/auth/register")
def register_user(user: UserCreate):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO users (email, hashed_password) VALUES (%s, %s) RETURNING id", (user.email, hashed_password))
            user_id = cursor.fetchone()[0]
        conn.commit()
        return {"message": "User registered successfully", "user_id": user_id}
    finally:
        release_connection(conn)

@app.post("/auth/login")
def login_user(user: UserCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, hashed_password FROM users WHERE email = %s", (user.email,))
            result = cursor.fetchone()
            if result and bcrypt.checkpw(user.password.encode('utf-8'), result[1].encode('utf-8')):
                token = create_token(result[0])
                return {"token": token}
    finally:
        release_connection(conn)
    raise HTTPException(status_code=400, detail="Invalid credentials")

@app.post("/auth/logout")
def logout_user(user_id: int):
    redis_client.delete(f"token:{user_id}")
    return {"message": "User logged out"}



@app.patch("/profile/edit")
def update_profile(user_data: UserUpdate, authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization token is required")
    
    token = authorization.split("Bearer ")[-1]
    user_id = verify_token(token)

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # Проверяем, существует ли пользователь
            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            # Обновляем email, если передан
            if user_data.email:
                cursor.execute("UPDATE users SET email = %s WHERE id = %s", (user_data.email, user_id))
            
            # Обновляем пароль и отзываем все токены
            if user_data.password:
                hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (hashed_password, user_id))

                # Удаляем все токены пользователя из Redis
                redis_client.delete(f"token:{user_id}")
            
        conn.commit()
        return {"message": "Profile updated successfully. Please log in again."}
    finally:
        release_connection(conn)




# Эндпойнты для транзакций
@app.post("/transactions")
def create_transaction(transaction: TransactionCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO transactions (user_id, amount, category_id, type) VALUES (%s, %s, %s, %s) RETURNING id",
                (transaction.user_id, transaction.amount, transaction.category_id, transaction.type)
            )
            transaction_id = cursor.fetchone()[0]
        conn.commit()
        return {"transaction_id": transaction_id}
    finally:
        release_connection(conn)

@app.get("/transactions")
def get_transactions():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM transactions")
            transactions = cursor.fetchall()
        return transactions
    finally:
        release_connection(conn)

@app.get("/transactions/{id}")
def get_transaction(id: int):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM transactions WHERE id = %s", (id,))
            transaction = cursor.fetchone()
            if not transaction:
                raise HTTPException(status_code=404, detail="Transaction not found")
        return transaction
    finally:
        release_connection(conn)

@app.patch("/transactions/{id}")
def update_transaction(id: int, transaction: TransactionUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE transactions SET amount = %s, category_id = %s, type = %s WHERE id = %s RETURNING id",
                (transaction.amount, transaction.category_id, transaction.type, id)
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Transaction not found")
        conn.commit()
        return {"message": "Transaction updated successfully"}
    finally:
        release_connection(conn)

@app.delete("/transactions/{id}")
def delete_transaction(id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM transactions WHERE id = %s", (id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Transaction not found")
        conn.commit()
        return {"message": "Transaction deleted successfully"}
    finally:
        release_connection(conn)



if __name__ == "__main__":
    create_tables()
    uvicorn.run(app, host="0.0.0.0", port=8000)

