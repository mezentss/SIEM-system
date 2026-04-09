# =============================================================================
# Dockerfile для SIEM Backend
# =============================================================================
# Сборка:
#   docker build -t siem-backend .
# 
# Запуск:
#   docker run -p 8000:8000 siem-backend

FROM python:3.11-slim

# Рабочая директория
WORKDIR /app

# Переменные окружения
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEM_DATABASE_URL=postgresql+psycopg2://siem_user:siem_password@postgres:5432/siem_db \
    SIEM_LOG_LEVEL=INFO

# Установка зависимостей системы
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Копирование зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода
COPY . .

# Создание директории для логов
RUN mkdir -p /app/logs

# Открытие порта
EXPOSE 8000

# Запуск приложения
CMD ["uvicorn", "siem_backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
