import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btct_agent.redactor import PLACEHOLDER, redact_line

PH = PLACEHOLDER


class TestRedactor(unittest.TestCase):
    def test_nmap_port_is_not_redacted(self):
        # The whole reason this module is tool-aware: a regression guard.
        red, degraded = redact_line("nmap -p 1-65535 10.0.0.5")
        self.assertFalse(degraded)
        self.assertIn("1-65535", red)
        self.assertNotIn(PH, red)

    def test_mysql_inline_password(self):
        red, _ = redact_line("mysql -uroot -pSuperSecret -h 10.0.0.5")
        self.assertIn(f"-p{PH}", red)
        self.assertNotIn("SuperSecret", red)

    def test_hydra_password_flag(self):
        red, _ = redact_line("hydra -l admin -p Hunter2 10.0.0.5 ssh")
        self.assertNotIn("Hunter2", red)
        self.assertIn(PH, red)

    def test_hydra_wordlist_flag_kept(self):
        # -P is a wordlist path, not a secret: must survive.
        red, _ = redact_line("hydra -l admin -P /usr/share/rockyou.txt 10.0.0.5 ssh")
        self.assertIn("rockyou.txt", red)

    def test_authorization_header(self):
        red, _ = redact_line("curl -H 'Authorization: Bearer abc123' http://x")
        self.assertNotIn("abc123", red)
        self.assertIn(PH, red)

    def test_url_credentials(self):
        red, _ = redact_line("curl http://admin:p@ssw0rd@10.0.0.5/")
        self.assertNotIn("p@ssw0rd", red)

    def test_impacket_hashes(self):
        red, _ = redact_line("secretsdump.py user@10.0.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertNotIn("31d6cfe0d16ae931b73c59d7e0c089c0", red)

    def test_long_flag_equals(self):
        red, _ = redact_line("tool --password=hunter2 --host x")
        self.assertIn(f"--password={PH}", red)
        self.assertNotIn("hunter2", red)

    def test_pipeline_uses_segment_context(self):
        # cat's args aren't secret; mysql's -p in the 2nd segment must redact.
        red, _ = redact_line("cat dump.sql | mysql -pSecret db")
        self.assertNotIn("Secret", red)

    def test_unbalanced_quotes_degraded(self):
        red, degraded = redact_line("hydra -p 'unterminated")
        self.assertTrue(degraded)

    def test_local_vs_shipped_diverge(self):
        original = "hydra -l admin -p Hunter2 10.0.0.5 ssh"
        red, _ = redact_line(original)
        self.assertNotEqual(original, red)  # local keeps original; shipped is redacted


if __name__ == "__main__":
    unittest.main()
