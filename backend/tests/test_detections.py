import unittest
import asyncio
from datetime import datetime, timedelta, timezone

from backend.app.main import AnalyzeRequest, Event, app, health, risk_score, run_rules


def event(*, minute: int, username: str = "alice", event_type: str = "ssh", outcome: str = "failed", port: int | None = None) -> Event:
    return Event(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute),
        source_ip="198.51.100.25",
        destination_ip="192.0.2.10",
        username=username,
        event_type=event_type,
        outcome=outcome,
        destination_port=port,
    )


class DetectionTests(unittest.TestCase):
    def test_health_route_reports_demo_mode_and_unconfigured_integrations(self) -> None:
        result = asyncio.run(health())

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["mode"], "demo")
        self.assertFalse(result["external_intel_configured"])
        self.assertIn("/health", app.openapi()["paths"])

    def test_repeated_authentication_failures_include_explainable_evidence(self) -> None:
        rows = [event(minute=0, username="alice"), event(minute=1), event(minute=2, username="bob"), event(minute=3), event(minute=4)]
        alerts = run_rules(rows, AnalyzeRequest(events=rows, failed_login_threshold=5, login_window_minutes=5))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "repeated_auth_failures")
        self.assertEqual(alerts[0]["risk_score"], 35)
        self.assertIn("multiple_accounts_targeted", [item["signal"] for item in alerts[0]["evidence"]])

    def test_authentication_failures_outside_window_do_not_trigger(self) -> None:
        rows = [event(minute=0), event(minute=10), event(minute=20), event(minute=30), event(minute=40)]
        alerts = run_rules(rows, AnalyzeRequest(events=rows, failed_login_threshold=5, login_window_minutes=5))

        self.assertEqual(alerts, [])

    def test_port_scan_rule_counts_distinct_ports_in_window(self) -> None:
        rows = [event(minute=0, event_type="network", outcome="attempt", port=port) for port in range(22, 36)]
        alerts = run_rules(rows, AnalyzeRequest(events=rows, port_threshold=12, scan_window_minutes=3))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "port_scan")
        self.assertEqual(alerts[0]["risk_score"], 27)
        self.assertEqual(alerts[0]["evidence"][1]["observed"], 12)

    def test_risk_score_is_bounded_and_lists_contributions(self) -> None:
        score, evidence = risk_score(failed_logins=500, distinct_ports=500, multi_account=True, asset_criticality=20)

        self.assertEqual(score, 100)
        self.assertEqual([item["points"] for item in evidence], [40, 35, 15, 10])


if __name__ == "__main__":
    unittest.main()
