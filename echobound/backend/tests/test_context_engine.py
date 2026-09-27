import time

from echobound.context_engine import MaintenanceContextEngine


def test_quick_setup_and_status(storage):
    ctx = MaintenanceContextEngine(storage)
    ctx.quick_setup_business_hours("default", "UTC", "09:00", "18:00", weekdays=[0, 1, 2, 3, 4, 5, 6])
    status = ctx.current_status("default")
    assert status["configured"] is True
    assert "seconds_until_next_change" in status
    assert status["timezone"] == "UTC"


def test_no_config_fails_open(storage):
    ctx = MaintenanceContextEngine(storage)
    status = ctx.current_status("nonexistent-tenant")
    assert status["configured"] is False
    assert status["is_open"] is True
