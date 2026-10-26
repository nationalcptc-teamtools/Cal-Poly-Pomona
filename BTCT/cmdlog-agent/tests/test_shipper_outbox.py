import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.error

from btct_agent.shipper import MAX_BATCH_EVENTS, MAX_COMMAND_CHARS, Outbox, Shipper, clamp_batch_size, clamp_event, events_read


class TestOutbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "outbox.ndjson"

    def tearDown(self):
        self.tmp.cleanup()

    def test_append_persist_reload(self):
        ob = Outbox(self.path)
        ob.append([{"id": "a"}, {"id": "b"}])
        self.assertEqual(len(ob), 2)
        # New instance reloads from disk.
        ob2 = Outbox(self.path)
        self.assertEqual(len(ob2), 2)
        self.assertEqual(ob2.drain(1), [{"id": "a"}])

    def test_overflow_drops_oldest(self):
        ob = Outbox(self.path, max_events=3)
        ob.append([{"id": str(i)} for i in range(5)])
        self.assertEqual(len(ob), 3)
        self.assertEqual(ob.dropped, 2)
        # Oldest two dropped → newest three remain, in order.
        self.assertEqual([e["id"] for e in ob.drain(3)], ["2", "3", "4"])

    def test_commit_removes_from_front(self):
        ob = Outbox(self.path)
        ob.append([{"id": "a"}, {"id": "b"}, {"id": "c"}])
        ob.commit(2)
        self.assertEqual([e["id"] for e in ob.drain(9)], ["c"])


class TestShipperDrain(unittest.TestCase):
    """Exercise the flush/outbox logic directly (no threads)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "outbox.ndjson"

    def tearDown(self):
        self.tmp.cleanup()

    def _shipper(self, poster):
        return Shipper("http://x/api", "tok", "ws", Outbox(self.path), batch_size=25, poster=poster)

    def test_failed_flush_spools_then_recovers(self):
        calls = {"n": 0}

        def failing(url, token, workspace, events, timeout=5.0):
            raise ConnectionRefusedError("down")

        s = self._shipper(failing)
        s._flush([{"id": "a"}, {"id": "b"}])
        self.assertEqual(len(s.outbox), 2)
        self.assertFalse(s.online)
        self.assertGreater(s.backoff, 1.0)

        # Server recovers: a working poster drains the outbox oldest-first.
        sent = []

        def ok(url, token, workspace, events, timeout=5.0):
            sent.extend(events)
            calls["n"] += 1

        s._poster = ok
        s._drain_outbox()
        self.assertEqual(len(s.outbox), 0)
        self.assertEqual([e["id"] for e in sent], ["a", "b"])
        self.assertTrue(s.online)

    def test_successful_flush_counts_sent(self):
        def ok(url, token, workspace, events, timeout=5.0):
            pass
        s = self._shipper(ok)
        s._flush([{"id": "a"}])
        self.assertEqual(s.sent, 1)
        self.assertEqual(len(s.outbox), 0)


class TestOutboxDisk(unittest.TestCase):
    """The append-only file plus committed offset."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "outbox.ndjson"

    def tearDown(self):
        self.tmp.cleanup()

    def test_commit_survives_reload(self):
        ob = Outbox(self.path)
        ob.append([{"id": "a"}, {"id": "b"}, {"id": "c"}])
        ob.commit(2)
        ob2 = Outbox(self.path)
        self.assertEqual([e["id"] for e in ob2.drain(9)], ["c"])

    def test_append_and_commit_do_not_rewrite_the_file(self):
        ob = Outbox(self.path)
        ob.append([{"id": str(i)} for i in range(100)])
        size = self.path.stat().st_size
        inode = self.path.stat().st_ino
        ob.commit(10)
        ob.append([{"id": "x"}])
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertGreater(self.path.stat().st_size, size)
        self.assertGreater(int(self.path.with_name("outbox.ndjson.offset").read_text()), 0)

    def test_compacts_once_half_is_committed(self):
        ob = Outbox(self.path, compact_min_bytes=1)
        ob.append([{"id": str(i)} for i in range(10)])
        ob.commit(6)
        self.assertEqual(self.path.read_text().count("\n"), 4)
        self.assertEqual(self.path.with_name("outbox.ndjson.offset").read_text(), "0")
        self.assertEqual([e["id"] for e in Outbox(self.path).drain(9)], ["6", "7", "8", "9"])

    def test_empty_queue_truncates_the_file(self):
        ob = Outbox(self.path)
        ob.append([{"id": "a"}])
        ob.commit(1)
        self.assertEqual(self.path.stat().st_size, 0)

    def test_torn_last_line_is_skipped(self):
        self.path.write_text('{"id": "a"}\n{"id": "b"}\n{"id": "c')
        ob = Outbox(self.path)
        self.assertEqual([e["id"] for e in ob.drain(9)], ["a", "b"])
        ob.append([{"id": "d"}])
        self.assertEqual([e["id"] for e in Outbox(self.path).drain(9)], ["a", "b", "d"])

    def test_old_format_without_offset_loads_everything(self):
        self.path.write_text('{"id": "a"}\n{"id": "b"}\n')
        self.assertEqual(len(Outbox(self.path)), 2)

    def test_overflow_on_disk_keeps_newest(self):
        ob = Outbox(self.path, max_events=3)
        ob.append([{"id": str(i)} for i in range(5)])
        self.assertEqual([e["id"] for e in Outbox(self.path, max_events=3).drain(9)], ["2", "3", "4"])


def http_error(code):
    return urllib.error.HTTPError("http://x/api", code, "err", {}, None)


class TestShipperRejections(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "outbox.ndjson"
        self.now = [100.0]

    def tearDown(self):
        self.tmp.cleanup()

    def _shipper(self, poster, batch_size=25):
        return Shipper("http://x/api", "tok", "ws", Outbox(self.path), batch_size=batch_size,
                       poster=poster, clock=lambda: self.now[0])

    def test_oversized_batch_is_split_and_the_bad_event_dropped(self):
        sent, calls = [], []

        def poster(url, token, workspace, events, timeout=5.0):
            calls.append(len(events))
            if len(events) > 4 or any(e["id"] == "bad" for e in events):
                raise http_error(413)
            sent.extend(e["id"] for e in events)

        s = self._shipper(poster)
        batch = [{"id": str(i)} for i in range(12)]
        batch[7] = {"id": "bad"}
        s._flush(batch)
        self.assertEqual(sent, [str(i) for i in range(12) if i != 7])
        self.assertEqual(s.rejected, 1)
        self.assertEqual(s.sent, 11)
        self.assertEqual(len(s.outbox), 0)
        self.assertTrue(s.online)

    def test_a_poison_head_no_longer_blocks_the_outbox(self):
        def poster(url, token, workspace, events, timeout=5.0):
            if any(e["id"].startswith("big") for e in events):
                raise http_error(413)

        s = self._shipper(poster)
        s.outbox.append([{"id": "big1"}, {"id": "big2"}, {"id": "ok1"}, {"id": "ok2"}])
        s._drain_outbox()
        self.assertEqual(len(s.outbox), 0)
        self.assertEqual(s.rejected, 2)
        self.assertEqual(s.sent, 2)

    def test_retry_statuses_keep_events_and_do_not_split(self):
        for code in (401, 403, 404, 408, 409, 429, 500, 503):
            calls = []

            def poster(url, token, workspace, events, timeout=5.0):
                calls.append(len(events))
                raise http_error(code)

            if self.path.exists():
                self.path.unlink()
            s = self._shipper(poster)
            s._flush([{"id": "a"}, {"id": "b"}, {"id": "c"}])
            self.assertEqual(calls, [3], code)
            self.assertEqual(len(s.outbox), 3, code)
            self.assertEqual(s.rejected, 0, code)
            self.assertFalse(s.online, code)

    def test_split_keeps_order_when_a_later_half_hits_a_network_error(self):
        state = {"n": 0}
        sent = []

        def poster(url, token, workspace, events, timeout=5.0):
            state["n"] += 1
            if state["n"] == 1:
                raise http_error(413)  # whole batch too big
            if state["n"] == 3:
                raise ConnectionRefusedError("down")  # second half
            sent.extend(e["id"] for e in events)

        s = self._shipper(poster)
        s._flush([{"id": str(i)} for i in range(4)])
        self.assertEqual(sent, ["0", "1"])
        self.assertEqual([e["id"] for e in s.outbox.drain(9)], ["2", "3"])

    def test_batch_size_is_clamped_to_the_server_cap(self):
        self.assertEqual(MAX_BATCH_EVENTS, 200)
        self.assertEqual(clamp_batch_size(500), 200)
        self.assertEqual(clamp_batch_size(0), 1)
        self.assertEqual(clamp_batch_size(25), 25)
        self.assertEqual(self._shipper(lambda *a, **k: None, batch_size=1000).batch_size, 200)

    def test_a_batch_over_the_cap_is_sent_in_posts_of_at_most_200(self):
        calls, sent = [], []

        def poster(url, token, workspace, events, timeout=5.0):
            calls.append(len(events))
            sent.extend(e["id"] for e in events)
            return {"accepted": len(events), "skipped": 0}

        s = self._shipper(poster)
        s._flush([{"id": str(i)} for i in range(450)])
        self.assertEqual(calls, [200, 200, 50])
        self.assertEqual(sent, [str(i) for i in range(450)])
        self.assertEqual(s.sent, 450)
        self.assertEqual(len(s.outbox), 0)

    def test_events_the_server_did_not_read_are_sent_again(self):
        # A server that reads only the first 200 events and says so (the
        # silent loss with --batch-size 500).
        stored = []

        def poster(url, token, workspace, events, timeout=5.0):
            took = events[:200]
            stored.extend(e["id"] for e in took)
            return {"accepted": len(took), "skipped": 0}

        s = self._shipper(poster)
        s.outbox.append([{"id": str(i)} for i in range(300)])
        s.batch_size = 300  # as an unclamped caller would
        s._drain_outbox()
        self.assertEqual(stored, [str(i) for i in range(300)])
        self.assertEqual(len(s.outbox), 0)
        self.assertEqual(s.sent, 300)

    def test_skipped_events_count_as_rejected_and_a_short_read_keeps_the_rest(self):
        def poster(url, token, workspace, events, timeout=5.0):
            # Reads 3 of what it gets, one of them invalid.
            return {"accepted": 2, "skipped": 1}

        s = self._shipper(poster)
        s._flush([{"id": str(i)} for i in range(5)])
        self.assertEqual(s.rejected, 2)
        self.assertEqual(s.sent, 3)
        self.assertEqual(len(s.outbox), 0)
        self.assertEqual(events_read(None, 7), (7, 0))
        self.assertEqual(events_read({"accepted": "x"}, 7), (7, 0))
        self.assertEqual(events_read({"accepted": 9, "skipped": 0}, 7), (7, 0))

    def test_a_reply_that_reads_nothing_keeps_the_batch_and_backs_off(self):
        s = self._shipper(lambda *a, **k: {"accepted": 0, "skipped": 0})
        s._flush([{"id": "a"}, {"id": "b"}])
        self.assertEqual(len(s.outbox), 2)
        self.assertFalse(s.online)

    def test_failure_sets_a_backoff_window(self):
        def down(url, token, workspace, events, timeout=5.0):
            raise ConnectionRefusedError("down")

        s = self._shipper(down)
        s._flush([{"id": "a"}])
        self.assertTrue(s.backing_off())
        self.now[0] += s.backoff + 0.01
        self.assertFalse(s.backing_off())

    def test_flush_queues_behind_a_nonempty_outbox_during_backoff(self):
        def down(url, token, workspace, events, timeout=5.0):
            raise ConnectionRefusedError("down")

        s = self._shipper(down)
        s._flush([{"id": "a"}])
        s._flush([{"id": "b"}])
        self.assertEqual([e["id"] for e in s.outbox.drain(9)], ["a", "b"])


class TestClamp(unittest.TestCase):
    def test_long_command_is_cut_to_the_server_limit(self):
        ev = clamp_event({"id": "a", "command": "x" * 30000, "cwd": "/" * 900})
        self.assertEqual(len(ev["command"]), MAX_COMMAND_CHARS)
        self.assertEqual(len(ev["cwd"]), 512)

    def test_short_event_is_untouched(self):
        ev = {"id": "a", "command": "nmap -sV 10.0.0.1"}
        self.assertIs(clamp_event(ev), ev)


if __name__ == "__main__":
    unittest.main()
