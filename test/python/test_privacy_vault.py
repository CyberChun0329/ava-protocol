import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("privacy_vault", ROOT / "scripts/privacy_vault.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


def identifier(number):
    return "0x" + format(number, "064x")


class PrivacyVaultTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.store = self.base / "vault"
        self.key = os.urandom(32)
        self.allowed = True
        self.calls = []
        self.vault = privacy.Vault(self.store, self.key, self.authorize)
        self.payload = b"Confidential manuscript and reviewer report.\n"
        self.metadata = {"originalFilename": "private-alice-review.txt",
                         "reviewerIdentity": "alice@example.invalid", "nested": {"token": "secret-token"}}
        self.context = {"app_id": identifier(1), "case_id": identifier(2),
                        "policy_id": 1, "material_class": identifier(3)}
        self.actor = {"persona": identifier(4), "role": identifier(5), "purpose": identifier(6)}

    def authorize(self, receipt, persona, role, purpose):
        self.calls.append((receipt, persona, role, purpose))
        return self.allowed

    def put(self, **overrides):
        args = dict(self.context, payload=self.payload, metadata=self.metadata)
        args.update(overrides)
        return self.vault.put(**args)

    def path(self, receipt):
        return self.store / (receipt["resourceId"][2:] + ".json")

    def mutate(self, receipt, operation):
        path = self.path(receipt)
        record = json.loads(path.read_bytes())
        operation(record)
        path.write_bytes(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())

    def test_round_trip_receipt_commitment_and_private_disk_contents(self):
        receipt = self.put()
        self.assertEqual(set(receipt), {"resourceId", "appId", "caseId", "policyId", "materialClass",
                                        "ciphertextHash", "uri"})
        self.assertEqual(receipt, self.vault.receipt(receipt["resourceId"]))
        self.assertEqual(receipt["uri"], "ava-private:v1:" + receipt["resourceId"][2:])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.vault.read(receipt["resourceId"], **self.actor), (self.payload, self.metadata))
        self.assertEqual(self.calls, [(receipt, *self.actor.values())])
        stored = self.path(receipt).read_bytes()
        self.assertEqual(receipt["ciphertextHash"], "0x" + hashlib.sha256(stored).hexdigest())
        for secret in [self.payload, self.key, *[value.encode() for value in
                       ("private-alice-review.txt", "alice@example.invalid", "secret-token")]]:
            self.assertNotIn(secret, stored)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.path(receipt).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(list(self.store.iterdir())), 1)

    def test_transfer_exports_only_selected_authenticated_envelope_and_key(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        first, second = self.put(), self.put()
        transfer = self.vault.export_for_transfer(first["resourceId"], **self.actor)
        self.assertEqual(set(transfer), {"envelopeBase64", "contentKeyBase64"})
        encoded = base64.b64decode(transfer["envelopeBase64"], validate=True)
        key = base64.b64decode(transfer["contentKeyBase64"], validate=True)
        self.assertEqual(first["ciphertextHash"], "0x" + hashlib.sha256(encoded).hexdigest())
        self.assertNotEqual(key, self.key)
        record = json.loads(encoded)
        plaintext = AESGCM(key).decrypt(base64.b64decode(record["dataNonce"]),
                    base64.b64decode(record["ciphertext"]), privacy._aad(record["context"], b"content"))
        self.assertTrue(plaintext.endswith(self.payload))
        other = json.loads(self.path(second).read_bytes())
        with self.assertRaises(InvalidTag):
            AESGCM(key).decrypt(base64.b64decode(other["dataNonce"]), base64.b64decode(other["ciphertext"]),
                                privacy._aad(other["context"], b"content"))
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            self.vault.export_for_transfer(first["resourceId"], **self.actor)

    def test_no_cached_grants_and_revocation_is_immediate_on_next_read(self):
        receipt = self.put()
        resource = receipt["resourceId"]
        for _ in range(2):
            self.vault.read(resource, **self.actor)
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            self.vault.read(resource, **self.actor)
        self.assertEqual(len(self.calls), 3)

    def test_per_read_authorizer_does_not_replace_default_or_accept_truthy_values(self):
        receipt = self.put()
        observed = []

        def allow(actual, *scope):
            observed.append(actual)
            return True

        self.allowed = False
        self.assertEqual(self.vault.read(receipt["resourceId"], **self.actor, authorizer=allow)[0], self.payload)
        self.assertEqual(observed, [receipt])
        with self.assertRaises(privacy.AccessDenied):
            self.vault.read(receipt["resourceId"], **self.actor)
        with self.assertRaises(privacy.AccessDenied):
            self.vault.read(receipt["resourceId"], **self.actor, authorizer=lambda *_: {"allowed": True})

    def test_denial_and_callback_error_happen_before_decryption(self):
        receipt = self.put()
        for result in (False, None, 1, "yes"):
            with self.subTest(result=result), mock.patch.object(privacy.AESGCM, "decrypt") as decrypt:
                self.allowed = result
                with self.assertRaises(privacy.AccessDenied):
                    self.vault.read(receipt["resourceId"], **self.actor)
                decrypt.assert_not_called()
        error_vault = privacy.Vault(self.store, self.key,
                                    lambda *args: (_ for _ in ()).throw(RuntimeError("sensitive identity")))
        with mock.patch.object(privacy.AESGCM, "decrypt") as decrypt:
            with self.assertRaises(privacy.AccessDenied) as caught:
                error_vault.read(receipt["resourceId"], **self.actor)
            self.assertNotIn("sensitive", str(caught.exception))
            decrypt.assert_not_called()

    def test_wrong_key_fails_but_ciphertext_receipt_is_key_independent(self):
        receipt = self.put()
        wrong = privacy.Vault(self.store, os.urandom(32), self.authorize)
        self.assertEqual(wrong.receipt(receipt["resourceId"]), receipt)
        with self.assertRaises(privacy.VaultError):
            wrong.read(receipt["resourceId"], **self.actor)

    def test_each_encrypted_component_detects_tampering(self):
        for field in ("ciphertext", "wrappedKey", "wrapNonce", "dataNonce"):
            with self.subTest(field=field):
                receipt = self.put()
                def flip(record):
                    value = bytearray(base64.b64decode(record[field]))
                    value[0] ^= 1
                    record[field] = base64.b64encode(value).decode()
                self.mutate(receipt, flip)
                with self.assertRaises(privacy.VaultError):
                    self.vault.read(receipt["resourceId"], **self.actor)

    def test_all_public_context_is_authenticated(self):
        for field in ("appId", "caseId", "policyId", "materialClass"):
            with self.subTest(field=field):
                receipt = self.put()
                self.mutate(receipt, lambda record: record["context"].__setitem__(
                    field, 99 if field == "policyId" else identifier(99)))
                with self.assertRaises(privacy.VaultError):
                    self.vault.read(receipt["resourceId"], **self.actor)

    def test_resource_context_and_cross_record_ciphertext_swaps_fail(self):
        first, second = self.put(), self.put()
        record = json.loads(self.path(first).read_bytes())
        for field in ("wrappedKey", "ciphertext"):
            with self.subTest(field=field):
                target = self.put()
                self.mutate(target, lambda other: other.__setitem__(field, record[field]))
                with self.assertRaises(privacy.VaultError):
                    self.vault.read(target["resourceId"], **self.actor)
        self.path(second).write_bytes(self.path(first).read_bytes())
        with self.assertRaises(privacy.VaultError):
            self.vault.read(second["resourceId"], **self.actor)

    def test_identical_inputs_have_distinct_ciphertexts_and_random_ids(self):
        first, second = self.put(), self.put()
        self.assertNotEqual(first["resourceId"], second["resourceId"])
        self.assertNotEqual(first["ciphertextHash"], second["ciphertextHash"])
        one, two = (json.loads(self.path(item).read_bytes()) for item in (first, second))
        self.assertNotEqual(one["wrappedKey"], two["wrappedKey"])
        self.assertNotEqual(one["ciphertext"], two["ciphertext"])
        self.assertNotEqual(one["dataNonce"], two["dataNonce"])
        self.assertNotEqual(one["wrapNonce"], two["wrapNonce"])

    def test_put_is_exclusive_and_never_overwrites(self):
        receipt = self.put(resource_id=identifier(100))
        original = self.path(receipt).read_bytes()
        with self.assertRaises(privacy.VaultError):
            self.put(resource_id=identifier(100), payload=b"replacement")
        self.assertEqual(original, self.path(receipt).read_bytes())

    def test_invalid_context_and_actor_values_fail_closed(self):
        for field in ("app_id", "case_id", "material_class", "resource_id"):
            for value in (None, "../escape", identifier(1).upper(), "0x" + "0" * 64, "0x" + "f" * 63):
                if field == "resource_id" and value is None:
                    continue
                with self.subTest(field=field, value=value), self.assertRaises(privacy.VaultError):
                    self.put(**{field: value})
        for value in (0, -1, 2**256, True, "1"):
            with self.subTest(policy=value), self.assertRaises(privacy.VaultError):
                self.put(policy_id=value)
        receipt = self.put()
        for field in self.actor:
            actor = dict(self.actor, **{field: "../escape"})
            with self.assertRaises(privacy.VaultError):
                self.vault.read(receipt["resourceId"], **actor)
        self.assertEqual(self.calls, [])

    def test_size_boundary_counts_encrypted_metadata_and_payload(self):
        # Empty metadata encodes to two bytes plus the four-byte framing field.
        receipt = self.put(payload=b"x" * (privacy.MAX_PLAINTEXT_BYTES - 6), metadata={})
        self.assertEqual(len(self.vault.read(receipt["resourceId"], **self.actor)[0]),
                         privacy.MAX_PLAINTEXT_BYTES - 6)
        for payload, metadata in ((b"x" * (privacy.MAX_PLAINTEXT_BYTES - 5), {}),
                                  (b"", {"x": "x" * privacy.MAX_PLAINTEXT_BYTES})):
            with self.assertRaises(privacy.VaultError):
                self.put(payload=payload, metadata=metadata)

    def test_invalid_metadata_and_keys_are_rejected_without_storing(self):
        for metadata in ([], {1: "bad key"}, {"x": float("nan")}, {"x": b"bytes"}):
            with self.assertRaises(privacy.VaultError):
                self.put(metadata=metadata)
        for key in (b"short", "x" * 32, bytearray(32)):
            with self.assertRaises(privacy.VaultError):
                privacy.Vault(self.store, key, self.authorize)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_missing_corrupt_and_oversized_records_fail_closed(self):
        with self.assertRaises(privacy.VaultError):
            self.vault.read(identifier(88), **self.actor)
        for data in (b"", b"{}", b"null", b"\xff", b"{" + b"x" * privacy.MAX_RECORD_BYTES):
            receipt = self.put()
            self.path(receipt).write_bytes(data)
            with self.assertRaises(privacy.VaultError):
                self.vault.read(receipt["resourceId"], **self.actor)
        self.assertEqual(self.calls, [])

    def test_receipt_rejects_duplicate_fields_noncanonical_and_unknown_fields(self):
        receipt = self.put()
        path = self.path(receipt)
        original = path.read_bytes()
        for data in (original + b"\n", original.replace(b'"version":1', b'"version":1,"version":1'),
                     original[:-1] + b',"filename":"private.txt"}'):
            path.write_bytes(data)
            with self.assertRaises(privacy.VaultError):
                self.vault.receipt(receipt["resourceId"])

    def test_filesystem_path_symlink_hardlink_and_permissions_guards(self):
        with self.assertRaises(privacy.VaultError):
            privacy.Vault(self.base / ".." / "escape", self.key, self.authorize)
        link = self.base / "link"
        link.symlink_to(self.store, target_is_directory=True)
        with self.assertRaises(privacy.VaultError):
            privacy.Vault(link, self.key, self.authorize)
        with self.assertRaises(privacy.VaultError):
            privacy.Vault(link / "child", self.key, self.authorize)
        receipt = self.put()
        path = self.path(receipt)
        saved = self.base / "saved"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(privacy.VaultError):
            self.vault.read(receipt["resourceId"], **self.actor)
        path.unlink()
        os.link(saved, path)
        with self.assertRaises(privacy.VaultError):
            self.vault.receipt(receipt["resourceId"])
        saved.unlink()
        path.chmod(0o644)
        with self.assertRaises(privacy.VaultError):
            self.vault.receipt(receipt["resourceId"])
        self.store.chmod(0o755)
        with self.assertRaises(privacy.VaultError):
            self.vault.read(receipt["resourceId"], **self.actor)

    def test_root_replaced_by_symlink_after_initialization_is_rejected(self):
        receipt = self.put()
        moved = self.base / "moved"
        self.store.rename(moved)
        self.store.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(privacy.VaultError):
            self.vault.read(receipt["resourceId"], **self.actor)
        with self.assertRaises(privacy.VaultError):
            self.put()

    def test_failed_write_removes_partial_ciphertext(self):
        with mock.patch.object(privacy.os, "fsync", side_effect=OSError("disk failure")):
            with self.assertRaises(privacy.VaultError):
                self.put()
        self.assertEqual(list(self.store.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
