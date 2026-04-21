# Запуск тестов

## Установка зависимостей

```bash
cd backend
source ../.venv/bin/activate
pip install -r requirements.txt
```

## Запуск всех тестов

```bash
python -m pytest tests/ -v
```

## Запуск конкретных тестов

```bash
# Тесты правил анализа
python -m pytest tests/test_analysis_rules.py -v

# Тесты уведомлений
python -m pytest tests/test_notifications.py -v

# Интеграционные тесты с моками
python -m pytest tests/test_integration.py -v
```

## Запуск одного теста

```bash
python -m pytest tests/test_analysis_rules.py::TestMultipleFailedLoginsRule::test_no_events -v
```

## Покрытие кода

```bash
pip install coverage
coverage run -m pytest tests/
coverage report
coverage html
```

---

## Структура тестов

```
tests/
├── __init__.py
├── mocks.py                    # Фабрики моков для тестирования
├── test_analysis_rules.py      # Тесты правил анализа (18 тестов)
├── test_integration.py         # Интеграционные тесты с моками (27 тестов)
├── test_notifications.py       # Тесты уведомлений и классификатора (14 тестов)
└── README.md
```

---

## Статистика

- **Всего тестов:** 59
- **Правила анализа:** 18 тестов
- **Уведомления:** 14 тестов
- **Интеграционные тесты:** 27 тестов
- **Покрытие:** ~45%

---

## Моки для тестирования

Файл `mocks.py` содержит фабрики для создания тестовых данных:

### EventFactory
- `create_auth_failed()` — событие неудачной попытки входа
- `create_network_error()` — событие сетевой ошибки
- `create_service_crash()` — событие сбоя службы
- `create_batch_auth_failed(count)` — пакет событий аутентификации
- `create_batch_network_errors(count)` — пакет событий сетевых ошибок

### IncidentFactory
- `create_multiple_failed_logins()` — инцидент множественных попыток входа
- `create_network_errors()` — инцидент сетевых ошибок
- `create_service_crash()` — инцидент сбоя службы
- `create_resolved_incident()` — разрешённый инцидент

### UserFactory
- `create_admin()` — пользователь-администратор
- `create_operator()` — пользователь-оператор
- `create_employee()` — пользователь-сотрудник

### NotificationFactory
- `create_critical_incident_notification()` — уведомление о критическом инциденте
- `create_high_incident_notification()` — уведомление о высоком инциденте
- `create_test_notification()` — простое тестовое уведомление

### LogCollectorMock
- `get_mock_file_lines()` — тестовые строки лога
- `get_mock_macos_log_entries()` — тестовые записи macOS Unified Log

---

## Добавление новых тестов

1. Создайте файл `test_*.py` в папке `tests/`
2. Назовите класс тестов `Test*`
3. Назовите методы тестов `test_*`
4. Используйте `assert` для проверок

```python
import unittest
from tests.mocks import EventFactory, IncidentFactory

class TestMyFeature(unittest.TestCase):
    def test_something(self):
        # Создать тестовые данные через фабрики
        event = EventFactory.create_auth_failed()
        
        # Выполнить проверку
        self.assertEqual(event["event_type"], "authentication")

if __name__ == "__main__":
    unittest.main()
```
