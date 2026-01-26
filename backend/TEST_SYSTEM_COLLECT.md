# Проверка сбора системных логов macOS

## Endpoint

**POST /api/collect/system**

Параметры:
- `last_minutes` (int, default=5): Количество минут для получения логов (1-60)
- `max_lines` (int, default=200): Максимальное количество строк для обработки (1-5000)

## Проверка

### 1. Запуск сервера

```bash
cd backend
uvicorn siem_backend.main:app --reload
```

### 2. Сбор системных логов

```bash
curl -X POST "http://localhost:8000/api/collect/system?last_minutes=5&max_lines=200"
```

**Ожидаемый результат:**
```json
{
  "exported": true,
  "collected_count": 150,
  "saved_count": 150
}
```

### 3. Проверка событий

```bash
curl "http://localhost:8000/api/events?limit=10"
```

**Ожидаемый результат:** JSON-массив событий из системных логов macOS

### 4. Проверка файла

```bash
# Проверка что файл создан
ls -lh backend/logs/system.log

# Просмотр содержимого
head -20 backend/logs/system.log
```

### 5. Запуск анализа

```bash
curl -X POST "http://localhost:8000/api/analyze/run?since_minutes=60"
```

**Ожидаемый результат:**
```json
{
  "incidents_found": 2
}
```

### 6. Проверка инцидентов

```bash
curl "http://localhost:8000/api/incidents"
```

**Ожидаемый результат:** JSON-массив инцидентов, если найдены подозрительные события

## Полная цепочка проверки одной командой

```bash
# 1. Сбор логов
curl -X POST "http://localhost:8000/api/collect/system?last_minutes=5&max_lines=200"

# 2. Проверка событий
curl "http://localhost:8000/api/events?limit=5"

# 3. Анализ
curl -X POST "http://localhost:8000/api/analyze/run?since_minutes=60"

# 4. Инциденты
curl "http://localhost:8000/api/incidents"
```

## Проверка через Swagger UI

1. Откройте: http://localhost:8000/docs
2. Найдите раздел **collect**
3. Найдите endpoint **POST /api/collect/system**
4. Нажмите "Try it out"
5. Установите параметры:
   - `last_minutes`: 5
   - `max_lines`: 200
6. Нажмите "Execute"
7. Проверьте ответ: `exported: true`, `saved_count > 0`

## Что проверить

✅ `exported: true` - логи успешно экспортированы  
✅ `collected_count > 0` - события найдены в файле  
✅ `saved_count > 0` - события сохранены в БД  
✅ `/api/events` возвращает реальные системные события  
✅ `/api/analyze/run` находит инциденты (если есть подозрительные события)  

## Устранение проблем

### Если exported = false

**Причины:**
- Команда `log` не найдена (не macOS)
- Нет доступа к логам (требуются разрешения)

**Решение:**
- Убедитесь, что запускаете на macOS
- Проверьте доступ к команде: `which log`
- Попробуйте выполнить вручную: `log show --style syslog --last 5m`

### Если collected_count = 0

**Причины:**
- Файл пустой или не создан
- Формат логов не распознан парсером

**Решение:**
- Проверьте содержимое `backend/logs/system.log`
- Убедитесь, что файл не пустой
- Проверьте формат логов (должен быть syslog)

### Если saved_count = 0

**Причины:**
- Ошибка сохранения в БД
- События не прошли валидацию

**Решение:**
- Проверьте логи сервера
- Убедитесь, что БД инициализирована
- Проверьте структуру событий через `/api/events`
