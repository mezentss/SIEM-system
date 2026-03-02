"""
Unit-тесты для системы уведомлений и нормализации событий.
"""

import unittest
from unittest.mock import Mock

from siem_backend.services.notifications import get_telegram_advice, incident_text_ru
from siem_backend.services.normalization import EventClassifier
from siem_backend.data.models import Incident


class TestTelegramAdvice(unittest.TestCase):
    """Тесты для советов в Telegram уведомлениях."""

    def test_critical_advice(self):
        """Тест: совет для critical уровня."""
        advice = get_telegram_advice("critical")
        
        self.assertIn("ЧТО ДЕЛАТЬ НЕМЕДЛЕННО", advice)
        self.assertIn("Сохраните все открытые файлы", advice)
        self.assertIn("ЗВОНИТЕ", advice)
        self.assertIn("+7 (999) 123-45-67", advice)
        self.assertIn("⏰ Не откладывайте", advice)

    def test_high_advice(self):
        """Тест: совет для high уровня."""
        advice = get_telegram_advice("high")
        
        self.assertIn("ПЛАН ДЕЙСТВИЙ", advice)
        self.assertIn("Сохраните все файлы", advice)
        self.assertIn("Перезагрузите компьютер", advice)
        self.assertIn("звоните", advice)
        self.assertIn("+7 (999) 123-45-67", advice)

    def test_medium_advice_empty(self):
        """Тест: для medium совета нет (пустая строка)."""
        advice = get_telegram_advice("medium")
        
        self.assertEqual(advice, "")

    def test_low_advice_empty(self):
        """Тест: для low совета нет (пустая строка)."""
        advice = get_telegram_advice("low")
        
        self.assertEqual(advice, "")

    def test_unknown_severity(self):
        """Тест: неизвестная серьёзность — пустая строка."""
        advice = get_telegram_advice("unknown")
        
        self.assertEqual(advice, "")


class TestIncidentTextRu(unittest.TestCase):
    """Тесты для формирования текста инцидента на русском."""

    def test_multiple_failed_logins(self):
        """Тест: текст для множественных попыток входа."""
        incident = Incident(
            id=1,
            incident_type="multiple_failed_logins",
            severity="high",
            description="Test",
            details={"count": 5}
        )
        
        text = incident_text_ru(incident)
        
        self.assertIn("неуспешные попытки входа", text)

    def test_repeated_network_errors(self):
        """Тест: текст для сетевых ошибок."""
        incident = Incident(
            id=1,
            incident_type="repeated_network_errors",
            severity="high",
            description="Test",
            details={"events_count": 15, "window_minutes": 10}
        )
        
        text = incident_text_ru(incident)
        
        self.assertIn("повторяющиеся сетевые ошибки", text)
        self.assertIn("15", text)
        self.assertIn("10", text)

    def test_service_crash_with_name(self):
        """Тест: текст для сбоя службы с именем."""
        incident = Incident(
            id=1,
            incident_type="service_crash_or_restart",
            severity="critical",
            description="Test",
            details={"service": "nginx"}
        )
        
        text = incident_text_ru(incident)
        
        self.assertIn("сбой или перезапуск службы", text)
        self.assertIn("nginx", text)

    def test_service_crash_without_name(self):
        """Тест: текст для сбоя службы без имени."""
        incident = Incident(
            id=1,
            incident_type="service_crash_or_restart",
            severity="critical",
            description="Test",
            details={}
        )
        
        text = incident_text_ru(incident)
        
        self.assertIn("сбой или перезапуск службы", text)
        self.assertNotIn("nginx", text)


class TestEventClassifier(unittest.TestCase):
    """Тесты для классификатора событий."""

    def test_auth_keywords(self):
        """Тест: ключевые слова аутентификации."""
        test_cases = [
            "Failed password for user admin",
            "Authentication failure",
            "Invalid password",
            "Login failed",
            "Unauthorized access",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "authentication")

    def test_network_keywords(self):
        """Тест: ключевые слова сети."""
        test_cases = [
            "Connection timeout to 10.0.0.5",
            "DNS resolution failed",
            "Socket connection refused",
            "Network unreachable",
            "TCP handshake timeout",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "network")

    def test_service_keywords(self):
        """Тест: ключевые слова служб."""
        test_cases = [
            "nginx.service crashed",
            "systemd: Service restart",
            "Daemon terminated",
            "Launchd: exited",
            "Kernel panic",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "service")

    def test_source_category_service(self):
        """Тест: категория источника service."""
        test_cases = [
            ("systemd[1]: nginx.service crashed", {"process": "systemd"}),
            ("launchd: Service exited", {"process": "launchd"}),
            ("Service nginx failed to start", {}),
        ]
        
        for message, raw_data in test_cases:
            with self.subTest(message=message):
                category = EventClassifier.classify_source_category(message, raw_data, "linux")
                self.assertEqual(category, "service")

    def test_source_category_user_process(self):
        """Тест: категория источника user_process."""
        test_cases = [
            ("nginx.service: Main process exited", {"process": "nginx"}),
            ("Application crashed", {"application": "zoom"}),
            ("User process terminated", {}),
        ]
        
        for message, raw_data in test_cases:
            with self.subTest(message=message):
                category = EventClassifier.classify_source_category(message, raw_data, "linux")
                self.assertEqual(category, "user_process")


if __name__ == "__main__":
    unittest.main()
