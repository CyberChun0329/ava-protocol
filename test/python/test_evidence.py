import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("evidence", ROOT / "scripts/evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "report.md"
        self.source.write_bytes("Actual UTF-8 report bytes.\n评审材料\n".encode())
        self.store = self.base / "store"

    def test_round_trip_and_idempotent_receipt(self):
        record = evidence.put(self.store, self.source)
        status, data = evidence.inspect(self.store, record["uri"])
        self.assertEqual(status["status"], "available")
        self.assertEqual(data, self.source.read_bytes())
        self.assertEqual(evidence.put(self.store, self.source), record)
        payload, _ = evidence.locations(self.store, record["uri"])
        self.assertEqual(payload.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o700)

    def test_missing_and_tampered_bytes_are_distinct_from_decision(self):
        record = evidence.put(self.store, self.source)
        payload, metadata = evidence.locations(self.store, record["uri"])
        payload.write_bytes(b"changed")
        status, data = evidence.inspect(self.store, record["uri"])
        self.assertEqual(status["status"], "integrity_mismatch")
        self.assertIsNone(data)
        with self.assertRaises(ValueError):
            evidence.put(self.store, self.source)
        payload.unlink()
        self.assertEqual(evidence.inspect(self.store, record["uri"])[0]["status"], "unavailable")
        self.assertTrue(metadata.exists())
        with self.assertRaises(ValueError):
            evidence.put(self.store, self.source)

    def test_receipt_mutation_is_detected(self):
        record = evidence.put(self.store, self.source)
        _, metadata = evidence.locations(self.store, record["uri"])
        modified = dict(record, byteLength=0)
        metadata.write_text(json.dumps(modified))
        self.assertEqual(evidence.inspect(self.store, record["uri"])[0]["status"], "integrity_mismatch")

    def test_path_escape_and_symlinks_are_rejected(self):
        for invalid in ("../outside", "/private/tmp/outside"):
            with self.assertRaises(ValueError):
                evidence.local(invalid)
        link = self.base / "linked"
        link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            evidence.put(self.store, link)
        for uri in ("../payload", "ava-evidence:sha256:" + "0" * 63, "ava-evidence:sha256:" + "0" * 64 + "/x"):
            with self.assertRaises(ValueError):
                evidence.inspect(self.store, uri)


if __name__ == "__main__":
    unittest.main()
