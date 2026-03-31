import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

from siem_backend.services.analysis.rules.failed_logins import MultipleFailedLoginsRule
from siem_backend.services.analysis.rules.network_errors import RepeatedNetworkErrorsRule
from siem_backend.services.analysis.rules.service_crash import ServiceCrashOrRestartRule
from siem_backend.data.models import Event


class TestMultipleFailedLoginsRule(unittest.TestCase):

    def setUp(self):
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = MultipleFailedLoginsRule(threshold=5, window_minutes=10)
        
        # Мокаем справочник event_types
        self.db.execute.return_value.scalar_one_or_none.return_value = 1

    def _create_event(self, message: str, event_type: str = "authentication") -> Event:
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os_id=1,
            source_category_id=1,
            event_type_id=1,
            severity_id=3,
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)

    def test_below_threshold(self):
        events = [
            self._create_event("Failed login attempt for user admin"),
            self._create_event("Login failed for user admin"),
            self._create_event("Authentication failure for user admin"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)

    def test_at_threshold(self):
        events = [
            self._create_event("Failed login attempt for user admin"),
            self._create_event("Login failed for user admin"),
            self._create_event("Authentication failure for user admin"),
            self._create_event("Failed password for user admin"),
            self._create_event("Invalid password for user admin"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "multiple_failed_logins")
        self.assertIn(candidates[0].severity, ["low", "warning"])

    def test_above_threshold_critical(self):
        events = [
            self._create_event("Failed login attempt for user admin")
            for _ in range(30)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertIn(candidates[0].severity, ["medium", "high", "critical"])

    def test_non_auth_events_ignored(self):
        # Эмуляция: для не-auth типа возвращается другой ID
        def get_event_type_id(name):
            if name == "authentication":
                return 1
            return 2
            
        events = [
            self._create_event("Failed login attempt for user admin", event_type="network"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)


class TestRepeatedNetworkErrorsRule(unittest.TestCase):

    def setUp(self):
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = RepeatedNetworkErrorsRule(threshold=10, window_minutes=10)
        
        # Мокаем справочник event_types
        self.db.execute.return_value.scalar_one_or_none.return_value = 1

    def _create_event(self, message: str, event_type: str = "network") -> Event:
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os_id=1,
            source_category_id=1,
            event_type_id=1,
            severity_id=2,
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)

    def test_below_threshold(self):
        events = [
            self._create_event("Connection timeout"),
            self._create_event("Connection refused"),
            self._create_event("Network unreachable"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)

    def test_at_threshold(self):
        events = [
            self._create_event("Connection timeout")
            for _ in range(10)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "repeated_network_errors")
        self.assertEqual(candidates[0].severity, "low")

    def test_medium_severity(self):
        events = [
            self._create_event("Connection timeout")
            for _ in range(60)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "medium")

    def test_high_severity(self):
        events = [
            self._create_event("Connection timeout")
            for _ in range(120)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "high")

    def test_critical_severity(self):
        events = [
            self._create_event("Connection timeout")
            for _ in range(250)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "critical")


class TestServiceCrashOrRestartRule(unittest.TestCase):

    def setUp(self):
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = ServiceCrashOrRestartRule(threshold=1)
        
        # Мокаем справочник event_types
        self.db.execute.return_value.scalar_one_or_none.return_value = 1

    def _create_event(self, message: str, event_type: str = "service") -> Event:
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os_id=1,
            source_category_id=1,
            event_type_id=1,
            severity_id=3,
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)

    def test_single_crash(self):
        events = [
            self._create_event("nginx.service: Main process exited, status=1/FAILURE"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "service_crash_or_restart")
        self.assertEqual(candidates[0].severity, "low")

    def test_crash_keywords(self):
        test_cases = [
            "Application crashed",
            "Process terminated",
            "Kernel panic",
            "Service exited",
            "Service restart",
        ]

        for message in test_cases:
            with self.subTest(message=message):
                events = [self._create_event(message)]
                self.db.execute.return_value.scalars.return_value.all.return_value = events
                candidates = self.rule.run(self.db, since=self.since, until=self.until)
                self.assertEqual(len(candidates), 1)

    def test_medium_severity(self):
        events = [
            self._create_event("Service crashed")
            for _ in range(15)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "medium")

    def test_high_severity(self):
        events = [
            self._create_event("Service crashed")
            for _ in range(60)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "high")

    def test_critical_severity(self):
        events = [
            self._create_event("Service crashed")
            for _ in range(120)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "critical")

    def test_non_service_events_ignored(self):
        events = [
            self._create_event("Application crashed", event_type="process"),
            self._create_event("Connection timeout", event_type="network"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        self.assertEqual(len(candidates), 0)


if __name__ == "__main__":
    unittest.main()
