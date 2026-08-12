from types import SimpleNamespace
import unittest

from agent_safe.cli import build_receipt_payload


class AsyncReceiptContractTests(unittest.TestCase):
    def payload(self, status, fields=None):
        args = SimpleNamespace(
            tool="ssh_relay",
            change="long-job",
            target="host:test",
            reason=None,
            status=status,
            field=fields or [],
        )
        return build_receipt_payload(args)

    def test_legacy_done_receipt_remains_valid(self):
        self.assertEqual(self.payload("done")["status"], "done")

    def test_started_is_not_completed(self):
        item = self.payload("started", [("job", "build-app"), ("correlation_id", "op-1")])
        self.assertEqual(item["status"], "started")
        self.assertEqual(item["job"], "build-app")
        self.assertEqual(item["correlation_id"], "op-1")

    def test_terminal_event_keeps_correlation_fields(self):
        item = self.payload(
            "completed",
            [("job", "build-app"), ("correlation_id", "op-1"), ("event_id", "op-1:completed"), ("exit_code", "0")],
        )
        self.assertEqual(item["status"], "completed")
        self.assertEqual(item["event_id"], "op-1:completed")
        self.assertEqual(item["exit_code"], "0")


if __name__ == "__main__":
    unittest.main()
