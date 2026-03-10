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
python -m pytest tests/test_analysis_rules.py -v
python -m pytest tests/test_notifications.py -v
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
├── test_analysis_rules.py
├── test_notifications.py
└── README.md
```

---

## Статистика

- **Всего тестов:** 32
- **Правила анализа:** 18 тестов
- **Уведомления:** 14 тестов
- **Покрытие:** ~40%

---

## Добавление новых тестов

1. Создайте файл `test_*.py` в папке `tests/`
2. Назовите класс тестов `Test*`
3. Назовите методы тестов `test_*`
4. Используйте `assert` для проверок

```python
import unittest

class TestMyFeature(unittest.TestCase):
    def test_something(self):
        result = my_function()
        self.assertEqual(result, expected_value)

if __name__ == "__main__":
    unittest.main()
```
