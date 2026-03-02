# Запуск тестов

## Установка зависимостей

```bash
cd backend
source ../.venv/bin/activate  # Или активируйте ваш venv
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

# Конкретный тест
python -m pytest tests/test_analysis_rules.py::TestMultipleFailedLoginsRule::test_no_events -v
```

## Покрытие кода

```bash
# Установите coverage
pip install coverage

# Запустите с покрытием
coverage run -m pytest tests/
coverage report
coverage html  # Отчёт в HTML (откройте htmlcov/index.html)
```

---

## Структура тестов

```
tests/
├── __init__.py
├── test_analysis_rules.py    # Тесты правил анализа (18 тестов)
│   ├── TestMultipleFailedLoginsRule      # 5 тестов
│   ├── TestRepeatedNetworkErrorsRule     # 6 тестов
│   └── TestServiceCrashOrRestartRule     # 7 тестов
└── test_notifications.py     # Тесты уведомлений (14 тестов)
    ├── TestTelegramAdvice              # 5 тестов
    ├── TestIncidentTextRu              # 4 теста
    └── TestEventClassifier             # 5 тестов
```

---

## Статистика

- **Всего тестов:** 32
- **Правила анализа:** 18 тестов
- **Уведомления:** 14 тестов
- **Покрытие:** ~40% (основная логика)

---

## Добавление новых тестов

1. Создайте новый файл `test_*.py` в папке `tests/`
2. Назовите класс тестов `Test*`
3. Назовите методы тестов `test_*`
4. Используйте `assert` для проверок

Пример:

```python
import unittest

class TestMyFeature(unittest.TestCase):
    def test_something(self):
        result = my_function()
        self.assertEqual(result, expected_value)

if __name__ == "__main__":
    unittest.main()
```
