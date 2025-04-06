
---

```markdown
# 💰 Accounting for Finances

Простое API-приложение для ведения личных финансов. Реализовано на FastAPI, PostgreSQL и Redis. Пользователь может регистрироваться, логиниться и вести учёт своих доходов/расходов.

## 📦 Стек технологий

- **FastAPI** — фреймворк для быстрого создания API
- **PostgreSQL** — база данных для хранения пользователей, категорий и транзакций
- **Redis** — временное хранилище токенов (для авторизации)
- **JWT** — механизм авторизации

---

## ⚙️ Установка и запуск

### 1. Клонируй репозиторий

```bash
git clone https://github.com/your-username/accounting-for-finances.git
cd accounting-for-finances
```

### 2. Установи зависимости

```bash
pip install -r requirements.txt
```

### 3. Настрой .env (если используется)

Создай `.env` файл или задай переменные окружения:

```env
DB_NAME=your_db
DB_USER=your_user
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

REDIS_HOST=localhost
REDIS_PORT=6379

SECRET_KEY=your_secret_key
TOKEN_EXPIRE_MINUTES=30
```

### 4. Запусти PostgreSQL и Redis

Убедись, что Redis и PostgreSQL работают локально. Пример запуска Redis:

```bash
redis-server
```

### 5. Запусти сервер FastAPI

```bash
uvicorn main:app --reload
```

---

## 📚 Swagger-документация

После запуска открой в браузере:

```
http://127.0.0.1:8000/docs
```

Там ты найдёшь интерактивную документацию ко всем эндпоинтам.

---

## 🔐 Авторизация

1. Зарегистрируйся через `/auth/register`
2. Залогинься через `/auth/login` — получишь JWT-токен
3. Добавь в Swagger "Authorize" заголовок:

```
Bearer <your_token>
```

---

## 🧾 Основные эндпоинты

### Пользователи
- `POST /auth/register` — регистрация
- `POST /auth/login` — вход

### Транзакции
- `GET /transactions` — список всех транзакций пользователя
- `POST /transactions` — создать транзакцию
- `PATCH /transactions/{id}` — изменить
- `DELETE /transactions/{id}` — удалить

> Все транзакции жёстко привязаны к авторизованному пользователю

---

## 📁 Структура проекта (примерная)

```
main.py                 # основной файл приложения
models.py               # схемы Pydantic
auth.py                 # регистрация, логин
transactions.py         # работа с транзакциями
database.py             # соединение с PostgreSQL
redis_client.py         # подключение к Redis
```

---

## ✅ TODO

- [ ] Добавить фильтрацию по дате
- [ ] Поддержка категорий транзакций
- [ ] Графики и аналитика
- [ ] Docker контейнеризация

---

## 📬 Обратная связь

Если нашёл баг или хочешь предложить улучшение — пиши!
```

---

