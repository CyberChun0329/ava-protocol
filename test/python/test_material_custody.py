"""App-neutral encrypted custody over its public stdio interface."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/material_custody.py'

class MaterialCustodyTest(unittest.TestCase):
    def test_exact_encrypted_receipt_reopens_and_wrong_key_is_denied(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.tmp') as temporary:
            base = Path(temporary)
            key = base / 'key'
            key.write_bytes(os.urandom(32))
            key.chmod(0o600)
            def request(value, good=True):
                result = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(value).encode(),
                                        capture_output=True, cwd=ROOT, timeout=10)
                self.assertEqual(result.returncode == 0, good, result.stderr)
                if good:
                    return json.loads(result.stdout)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'E_CUSTODY\n')
            payload = b'Synthetic Spark lesson statement'
            fields = {'vaultPath': str(base / 'vault'), 'masterKeyFile': str(key)}
            receipt = request({**fields, 'operation': 'put', 'appId': '0x' + '01' * 32,
                               'caseId': '0x' + '02' * 32, 'materialClass': '0x' + '03' * 32,
                               'payloadBase64': base64.b64encode(payload).decode(), 'metadata': {'case': 'synthetic'}})
            encrypted = (base / 'vault' / (receipt['resourceId'][2:] + '.json')).read_bytes()
            self.assertNotIn(payload, encrypted)
            read = {**fields, 'operation': 'read', 'receipt': receipt}
            opened = request(read)
            self.assertEqual(base64.b64decode(opened['payloadBase64']), payload)
            self.assertEqual(opened['metadata'], {'case': 'synthetic'})
            request({**read, 'receipt': {**receipt, 'caseId': '0x' + '04' * 32}}, False)
            key.chmod(0o644)
            request(read, False)
            key.chmod(0o600)
            alias = base / 'key-link'
            alias.symlink_to(key)
            request({**read, 'masterKeyFile': str(alias)}, False)
            request({**read, 'masterKeyFile': '/etc/passwd'}, False)
            key.write_bytes(os.urandom(32))
            request(read, False)

if __name__ == '__main__':
    unittest.main()
