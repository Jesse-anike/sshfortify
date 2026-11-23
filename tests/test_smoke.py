import unittest

from main import analyze, parse_global_settings


class SSHFortifyTests(unittest.TestCase):
    def test_flags_weak_global_settings(self):
        report = analyze(
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "KbdInteractiveAuthentication yes\n"
            "X11Forwarding yes\n"
            "MaxAuthTries 8\n"
        )
        self.assertEqual(report["finding_count"], 5)

    def test_secure_baseline_has_no_findings(self):
        report = analyze(
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "X11Forwarding no\n"
            "MaxAuthTries 4\n"
        )
        self.assertEqual(report["findings"], [])

    def test_first_global_value_is_retained(self):
        parsed = parse_global_settings(
            "PermitRootLogin no\n"
            "PermitRootLogin yes\n"
        )
        self.assertEqual(parsed["settings"]["permitrootlogin"]["value"], "no")

    def test_match_block_is_not_treated_as_global(self):
        report = analyze(
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "X11Forwarding no\n"
            "MaxAuthTries 4\n"
            "Match User backup\n"
            "    PasswordAuthentication yes\n"
        )
        self.assertEqual(report["findings"], [])
        self.assertEqual(len(report["match_blocks"]), 1)
        self.assertTrue(report["manual_review_required"])

    def test_comment_does_not_set_value(self):
        report = analyze("# PermitRootLogin no\n")
        root_finding = next(item for item in report["findings"] if item["setting"] == "permitrootlogin")
        self.assertEqual(root_finding["observed"], "(not explicitly set)")


if __name__ == "__main__":
    unittest.main()
