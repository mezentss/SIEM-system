import subprocess
import os
from typing import Optional


class SystemLogExporter:

    def __init__(self, output_file: str = "./logs/system.log") -> None:
        self._output_file = output_file

    def export_logs(self, last_minutes: int = 5) -> bool:
        output_dir = os.path.dirname(self._output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError:
                return False

        cmd = [
            "log",
            "show",
            "--last",
            f"{last_minutes}m",
            "--info",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.stdout:
                with open(self._output_file, "w") as f:
                    f.write(result.stdout)
                return True

            if result.returncode != 0:
                if result.stderr and "permission" in result.stderr.lower():
                    pass
                return False

        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            return False
        except OSError:
            return False
        except Exception:
            return False

        return False

    def get_output_path(self) -> str:
        return self._output_file
