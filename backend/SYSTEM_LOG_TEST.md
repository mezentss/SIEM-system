# Проверка сбора реальных логов macOS

## Endpoint

**POST /api/collect/system**

Параметры:
- `last_minutes` (int, default=5): Количество минут для получения логов (1-60)
- `max_lines` (int, default=200): Максимальное количество строк для обработки (1-5000)

## Проверка через curl

### 1. Базовый запрос
```bash
curl -X POST "http://localhost:8000/api/collect/system"
```

**Ожидаемый результат:**
```json
{
  "exported": true,
  "collected_count": 150,
  "saved_count": 150
}
```

### 2. С параметрами
```bash
curl -X POST "http://localhost:8000/api/collect/system?last_minutes=10&max_lines=500"
```

### 3. Проверка файла логов
```bash
# Проверка что файл создан
ls -lh backend/logs/system.log

# Просмотр последних строк
tail -20 backend/logs/system.log
```

### 4. Проверка событий в БД
```bash
curl "http://localhost:8000/api/events?limit=10"
```

### 5. Запуск анализа
```bash
curl -X POST "http://localhost:8000/api/analyze/run?since_minutes=60"
```

### 6. Проверка инцидентов
```bash
curl "http://localhost:8000/api/incidents"
```

## Полная цепочка проверки

```bash
# 1. Сбор реальных логов
curl -X POST "http://localhost:8000/api/collect/system?last_minutes=5&max_lines=200"

# 2. Проверка событий
curl "http://localhost:8000/api/events?limit=5"

# 3. Запуск анализа
curl -X POST "http://localhost:8000/api/analyze/run?since_minutes=60"

# 4. Проверка инцидентов
curl "http://localhost:8000/api/incidents"

# 5. Проверка уведомлений
curl "http://localhost:8000/api/notifications"
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
7. Проверьте ответ

## Ожидаемое поведение

### Успешный сбор
- `exported: true` - логи успешно экспортированы
- `collected_count > 0` - события найдены в файле
- `saved_count > 0` - события сохранены в БД

### Если нет доступа к логам
- `exported: false` - экспорт не удался
- `error: "Failed to export system logs"` - описание ошибки

**Примечание:** На macOS команда `log show` может требовать разрешений. 
В учебном проекте это нормально - система будет работать с доступными логами.
