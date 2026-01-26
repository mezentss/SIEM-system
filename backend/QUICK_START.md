# Быстрый старт SIEM Backend

## Запуск

```bash
cd backend
uvicorn siem_backend.main:app --reload
```

## Проверка через curl

### 1. Health check
```bash
curl http://localhost:8000/api/health
```

### 2. Сбор логов из файла
```bash
curl -X POST "http://localhost:8000/api/collect/file?file_path=./logs/system.log&max_lines=100"
```

### 3. Получение событий
```bash
curl "http://localhost:8000/api/events?limit=10"
```

### 4. Запуск анализа
```bash
curl -X POST "http://localhost:8000/api/analyze/run?since_minutes=60"
```

### 5. Получение инцидентов
```bash
curl "http://localhost:8000/api/incidents"
```

### 6. Получение уведомлений
```bash
curl "http://localhost:8000/api/notifications"
```

## Swagger UI

Откройте: http://localhost:8000/docs

## Важно

При первом запуске БД автоматически пересоздается с актуальной схемой (включая `source_category`).
