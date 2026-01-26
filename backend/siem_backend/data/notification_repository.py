from __future__ import annotations

from typing import Sequence

from sqlalchemy.orm import Session

from siem_backend.data.models import Notification


class NotificationRepository:
    def add(self, db: Session, notification: Notification) -> Notification:
        db.add(notification)
        db.commit()
        db.refresh(notification)
        return notification

    def add_many(self, db: Session, notifications: Sequence[Notification]) -> int:
        if not notifications:
            return 0

        db.add_all(list(notifications))
        db.commit()
        return len(notifications)
