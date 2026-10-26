import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from btct_agent.spool import Correlator, SpoolReader, parse_record


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def pre_line(eid, pid, ts, cmd, cwd="/root"):
    return f"btct1\tpre\t{eid}\t{pid}\t{ts}\t{_b64(cmd)}\t{_b64(cwd)}\n"


def post_line(eid, exit_code, ts):
    return f"btct1\tpost\t{eid}\t{exit_code}\t{ts}\n"


class TestParse(unittest.TestCase):
    def test_pre(self):
        rec = parse_record(pre_line("e1", 42, "1000.5", "nmap -sV x"))
        self.assertEqual(rec["type"], "pre")
        self.assertEqual(rec["command"], "nmap -sV x")
        self.assertEqual(rec["pid"], 42)
        self.assertAlmostEqual(rec["ts"], 1000.5)

    def test_comma_decimal(self):
        rec = parse_record(pre_line("e1", 42, "1000,5", "x"))
        self.assertAlmostEqual(rec["ts"], 1000.5)

    def test_malformed(self):
        self.assertIsNone(parse_record("garbage"))
        self.assertIsNone(parse_record(""))
        self.assertIsNone(parse_record("btct1\tpre\ttooShort"))


class TestCorrelator(unittest.TestCase):
    def test_pre_post_join(self):
        c = Correlator()
        starts = c.feed(parse_record(pre_line("e1", 1, "100.0", "nmap x")))
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["kind"], "start")
        self.assertIsNone(starts[0]["exit_code"])
        self.assertEqual(starts[0]["started_at"], 100000)

        completes = c.feed(parse_record(post_line("e1", 0, "102.5")))
        self.assertEqual(len(completes), 1)
        ev = completes[0]
        self.assertEqual(ev["kind"], "complete")
        self.assertEqual(ev["exit_code"], 0)
        self.assertEqual(ev["duration_ms"], 2500)
        self.assertEqual(ev["command"], "nmap x")

    def test_orphan_post_is_partial(self):
        c = Correlator()
        out = c.feed(parse_record(post_line("nope", 1, "5.0")))
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("partial"))
        self.assertIsNone(out[0]["command"])

    def test_sweep_drops_stale(self):
        c = Correlator()
        c.feed(parse_record(pre_line("old", 1, "1.0", "x")))
        c.sweep(older_than_ts=100.0)
        self.assertEqual(len(c.pending), 0)


class TestSpoolReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.spool = Path(self.tmp.name) / "spool"
        self.spool.mkdir()
        self.offsets = Path(self.tmp.name) / "offsets.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_then_resumes_without_dup(self):
        f = self.spool / f"shell.{os.getpid()}"
        f.write_text(pre_line("e1", os.getpid(), "1.0", "nmap x"))
        r = SpoolReader(self.spool, self.offsets)
        recs = r.poll()
        self.assertEqual(len(recs), 1)
        # Second poll with no new bytes → nothing.
        self.assertEqual(r.poll(), [])
        # Append more; only the new record is read.
        with f.open("a") as fh:
            fh.write(post_line("e1", 0, "2.0"))
        recs2 = r.poll()
        self.assertEqual(len(recs2), 1)
        self.assertEqual(recs2[0]["type"], "post")

    def test_partial_line_not_consumed(self):
        f = self.spool / f"shell.{os.getpid()}"
        f.write_text("btct1\tpre\te1\t1\t1.0\t" + _b64("nmap") + "\t" + _b64("/r"))  # no newline
        r = SpoolReader(self.spool, self.offsets)
        self.assertEqual(r.poll(), [])  # incomplete → wait
        with f.open("a") as fh:
            fh.write("\n")
        self.assertEqual(len(r.poll()), 1)

    def test_offset_persisted_across_instances(self):
        f = self.spool / f"shell.{os.getpid()}"
        f.write_text(pre_line("e1", os.getpid(), "1.0", "nmap x"))
        SpoolReader(self.spool, self.offsets).poll()
        # New reader instance loads the saved offset → no re-read.
        self.assertEqual(SpoolReader(self.spool, self.offsets).poll(), [])


if __name__ == "__main__":
    unittest.main()
