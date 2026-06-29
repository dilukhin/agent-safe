import unittest

from agent_safe.core.models import Risk
from agent_safe.core.risk import assess_command


class RiskTests(unittest.TestCase):
    def test_read_only_is_safe(self):
        a = assess_command("git status --short")
        self.assertEqual(a.risk, Risk.SAFE)
        self.assertFalse(a.state_changing)

    def test_rm_rf_is_critical(self):
        a = assess_command("rm -rf project")
        self.assertEqual(a.risk, Risk.CRITICAL)
        self.assertTrue(a.state_changing)

    def test_unknown_is_high_attention(self):
        a = assess_command("frobnicate resource-123")
        self.assertEqual(a.risk, Risk.UNKNOWN)
        self.assertEqual(a.required_next_step, "inspect-docs-and-read-only-first")

    def test_yc_delete_is_critical(self):
        a = assess_command("yc compute instance delete --id abc")
        self.assertEqual(a.risk, Risk.CRITICAL)


if __name__ == "__main__":
    unittest.main()
