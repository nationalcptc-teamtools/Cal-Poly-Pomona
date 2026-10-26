import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btct_agent.matcher import command_programs, is_whitelisted, program_of, split_segments

WL = {"nmap", "hydra", "gobuster", "smbclient"}


class TestMatcher(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(command_programs("nmap -sV 10.0.0.5"), ["nmap"])

    def test_sudo(self):
        self.assertEqual(command_programs("sudo nmap -sV 10.0.0.5"), ["nmap"])

    def test_sudo_with_flags(self):
        self.assertEqual(command_programs("sudo -u root nmap -sV x"), ["nmap"])

    def test_env_prefix(self):
        self.assertEqual(command_programs("FOO=bar BAZ=1 nmap x"), ["nmap"])
        self.assertEqual(command_programs("env NMAP_PRIVILEGED=1 nmap x"), ["nmap"])

    def test_absolute_path(self):
        self.assertEqual(command_programs("/usr/bin/nmap -sV x"), ["nmap"])

    def test_pipeline_match_on_later_segment(self):
        matched, progs = is_whitelisted("cat hosts.txt | nmap -iL -", WL)
        self.assertTrue(matched)
        self.assertIn("nmap", progs)

    def test_pipeline_no_match(self):
        matched, progs = is_whitelisted("echo hi | grep x", WL)
        self.assertFalse(matched)
        self.assertEqual(progs, [])

    def test_quoted_pipe_is_not_operator(self):
        # The pipe is inside quotes → single segment, program is grep (not WL).
        segs = split_segments('grep "a|b" file')
        self.assertEqual(len(segs), 1)
        self.assertEqual(program_of(segs[0]), "grep")

    def test_multiple_matches(self):
        matched, progs = is_whitelisted("gobuster dir -u x | nmap -", WL)
        self.assertTrue(matched)
        self.assertEqual(sorted(progs), ["gobuster", "nmap"])


if __name__ == "__main__":
    unittest.main()
