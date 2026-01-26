from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


class SystemLogExporter:
    """Экспортер системных логов macOS в файл."""

    def __init__(self, output_file: Optional[str] = None) -> None:
        """
        Инициализирует экспортер.

        Args:
            output_file: Путь к файлу для сохранения логов. По умолчанию: ./logs/system.log
        """
        self._output_file = output_file or "./logs/system.log"

    def export_logs(self, last_minutes: int = 5) -> bool:
        """
        Экспортирует системные логи macOS в файл.

        Args:
            last_minutes: Количество минут для получения логов (по умолчанию 5)

        Returns:
            True если экспорт успешен, False в противном случае
        """
        try:
            # Создаем директорию если не существует
            output_path = Path(self._output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Выполняем команду log show
            cmd = [
                "log",
                "show",
                "--style",
                "syslog",
                "--last",
                f"{last_minutes}m",
            ]

            # Запускаем команду и получаем вывод
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Если команда завершилась с ошибкой, но это может быть нормально
            # (например, нет доступа к некоторым логам без sudo)
            if result.returncode != 0:
                # Если есть вывод, все равно сохраняем его
                if result.stdout:
                    with output_path.open("w", encoding="utf-8") as f:
                        f.write(result.stdout)
                    return True
                # Если есть stderr, логируем, но не падаем
                if result.stderr:
                    # В учебном проекте просто игнорируем ошибки доступа
                    # В реальной системе здесь был бы логгер
                    pass
                return False

            # Сохраняем вывод в файл
            with output_path.open("w", encoding="utf-8") as f:
                f.write(result.stdout)

            return True

        except subprocess.TimeoutExpired:
            # Команда выполняется слишком долго
            return False
        except FileNotFoundError:
            # Команда log не найдена (не macOS или не установлена)
            return False
        except OSError:
            # Ошибка записи файла
            return False
        except Exception:
            # Любая другая ошибка
            return False

    def get_log_file_path(self) -> str:
        """Возвращает путь к файлу логов."""
        return self._output_file
