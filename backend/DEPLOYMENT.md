# Развёртывание SIEM-системы с PostgreSQL

## 📋 Содержание

1. [Архитектура](#архитектура)
2. [Быстрый старт (Docker)](#быстрый-старт-docker)
3. [Ручная установка](#ручная-установка)
4. [Миграция с SQLite](#миграция-с-sqlite)
5. [Настройка сети предприятия](#настройка-сети-предприятия)

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    Сервер предприятия                    │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │   Backend    │    │  PostgreSQL  │                  │
│  │  FastAPI     │◄──►│     БД       │                  │
│  │  :8000       │    │   :5432      │                  │
│  └──────┬───────┘    └──────────────┘                  │
│         │                                               │
└─────────┼───────────────────────────────────────────────┘
          │
    ┌─────┴─────┐
    │  Сеть     │
    │  WiFi     │
    └─────┬─────┘
          │
    ┌─────┴─────────────┐
    │                   │
┌───▼────┐        ┌────▼────┐
│Ноутбук │        │Ноутбук  │
│ 1      │        │ 2       │
│Frontend│        │Frontend │
└────────┘        └─────────┘
```

---

## 🚀 Быстрый старт (Docker)

### 1. Клонирование репозитория

```bash
git clone <repository-url>
cd SIEM-system/backend
```

### 2. Настройка конфигурации

```bash
cp .env.docker .env
# Отредактируйте .env при необходимости
```

### 3. Запуск

```bash
docker-compose up -d
```

### 4. Проверка

```bash
# Проверка здоровья PostgreSQL
docker-compose exec postgres pg_isready -U siem_user -d siem_db

# Проверка backend
curl http://localhost:8000/api/health

# Просмотр логов
docker-compose logs -f backend
```

### 5. Остановка

```bash
docker-compose down
```

---

## 🔧 Ручная установка

### 1. Установка PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

### 2. Создание пользователя и базы данных

```bash
sudo -u postgres psql

CREATE USER siem_user WITH PASSWORD 'siem_password';
CREATE DATABASE siem_db OWNER siem_user;
GRANT ALL PRIVILEGES ON DATABASE siem_db TO siem_user;
\q
```

### 3. Настройка backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Настройка .env
cp .env.example .env
# Отредактируйте SIEM_DATABASE_URL
```

### 4. Запуск

```bash
uvicorn siem_backend.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🔄 Миграция с SQLite

### Автоматическая миграция

```bash
cd backend
source .venv/bin/activate

# Миграция с автоматическим определением настроек
python -m siem_backend.scripts.migrate_to_postgres \
    --sqlite-db ./siem.db \
    --postgres-url postgresql+psycopg2://siem_user:siem_password@localhost:5432/siem_db
```

### Ручная миграция

1. Экспорт данных из SQLite:
```bash
sqlite3 siem.db .dump > backup.sql
```

2. Импорт в PostgreSQL:
```bash
psql -U siem_user -d siem_db -f backup.sql
```

---

## 🌐 Настройка сети предприятия

### 1. Настройка PostgreSQL для удалённого доступа

**Файл:** `/etc/postgresql/16/main/postgresql.conf`
```ini
listen_addresses = '*'
```

**Файл:** `/etc/postgresql/16/main/pg_hba.conf`
```
# Разрешить доступ из локальной сети
host    siem_db    siem_user    192.168.1.0/24    md5
```

**Перезапуск:**
```bash
sudo systemctl restart postgresql
```

### 2. Настройка backend на каждом устройстве

**Файл:** `.env` (на каждом ноутбуке)
```env
SIEM_DATABASE_URL=postgresql+psycopg2://siem_user:siem_password@192.168.1.100:5432/siem_db
```

### 3. Настройка frontend

**Файл:** `frontend/renderer/renderer.js`
```javascript
const API_BASE = 'http://192.168.1.100:8000';  // IP сервера
```

---

## 🔒 Безопасность

### 1. Смена паролей по умолчанию

```bash
# PostgreSQL
ALTER USER siem_user WITH PASSWORD 'новый_сложный_пароль';

# .env файл
SIEM_DATABASE_URL=postgresql+psycopg2://siem_user:новый_пароль@host:5432/siem_db
```

### 2. Ограничение доступа к .env

```bash
chmod 600 .env
```

### 3. Брандмауэр

```bash
# Разрешить только необходимые порты
sudo ufw allow 5432/tcp  # PostgreSQL (только для сервера)
sudo ufw allow 8000/tcp  # Backend API
sudo ufw enable
```

---

## 📊 Мониторинг

### pgAdmin

Откройте браузер: `http://localhost:5050`

- Email: `admin@siem.local`
- Password: `admin`

### Логи

```bash
# Backend
docker-compose logs -f backend

# PostgreSQL
docker-compose logs -f postgres
```

### Статистика

```bash
# Количество событий
psql -U siem_user -d siem_db -c "SELECT COUNT(*) FROM events;"

# Количество инцидентов
psql -U siem_user -d siem_db -c "SELECT COUNT(*) FROM incidents;"

# Размер базы данных
psql -U siem_user -d siem_db -c "SELECT pg_size_pretty(pg_database_size('siem_db'));"
```

---

## 🆘 Устранение неполадок

### PostgreSQL не запускается

```bash
docker-compose logs postgres
# Проверьте, что порт 5432 свободен
lsof -i :5432
```

### Backend не подключается к БД

```bash
# Проверьте соединение
psql -h localhost -U siem_user -d siem_db

# Проверьте .env
cat .env | grep DATABASE_URL
```

### Ошибка миграции

```bash
# Проверьте, что SQLite файл существует
ls -la siem.db

# Запустите с отладкой
python -m siem_backend.scripts.migrate_to_postgres --help
```
