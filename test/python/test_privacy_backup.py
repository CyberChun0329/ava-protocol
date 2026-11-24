import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import privacy_vault as privacy
import custody_credentials as credentials

spec = importlib.util.spec_from_file_location("privacy_backup", ROOT / "scripts/privacy_backup.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def identifier(number):
    return "0x" + format(number, "064x")


class PrivacyBackupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="custody-", dir=ROOT / ".tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.key = os.urandom(32)
        self.backup_key = os.urandom(32)
        self.allowed = True
        self.authorizations = []
        self.vault = privacy.Vault(self.base / "source", self.key, self.authorize)
        self.actor = {"persona": identifier(4), "role": identifier(5), "purpose": identifier(6)}
        self.payload = b"Synthetic confidential manuscript content.\n"
        self.metadata = {"originalFilename": "synthetic-alice.txt",
                         "identity": "alice@example.invalid", "note": "synthetic-confidential-note"}
        self.receipts = [self.vault.put(identifier(1), identifier(2), 1, identifier(3),
                                        self.payload, self.metadata)]
        self.receipts.append(self.vault.put(identifier(1), identifier(2), 1, identifier(7),
                                            b"Synthetic identity mapping", {"name": "Synthetic Alice"}))
        self.archive = self.base / "encrypted.backup"
        self.destination = self.base / "restored"

    def authorize(self, receipt, *scope):
        self.authorizations.append((receipt, scope))
        return self.allowed

    def create(self, **overrides):
        arguments = dict(vault=self.vault, receipts=self.receipts,
                         destination=self.archive, backup_key=self.backup_key, **self.actor)
        arguments.update(overrides)
        return backup.create_backup(**arguments)

    def restore(self, **overrides):
        arguments = dict(backup_path=self.archive, destination=self.destination,
                         backup_key=self.backup_key, master_key=self.key)
        arguments.update(overrides)
        return backup.restore_backup(**arguments)

    def test_roundtrip_preserves_ciphertext_receipts_content_and_private_permissions(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.create()
            restored_receipts = self.restore()
        self.assertEqual(restored_receipts, self.receipts)
        restored = privacy.Vault(self.destination, self.key, self.authorize)
        for receipt in self.receipts:
            resource = receipt["resourceId"]
            self.assertEqual(restored.receipt(resource), receipt)
            self.assertEqual(restored.read(resource, **self.actor), self.vault.read(resource, **self.actor))
            filename = resource[2:] + ".json"
            self.assertEqual((self.destination / filename).read_bytes(),
                             (self.vault.root / filename).read_bytes())
            self.assertEqual((self.destination / filename).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.getvalue(), "")
        encoded = self.archive.read_bytes()
        for secret in (self.key, self.backup_key, self.payload, b"synthetic-alice.txt",
                       b"alice@example.invalid", b"synthetic-confidential-note", b"Synthetic Alice",
                       self.receipts[0]["resourceId"].encode()):
            self.assertNotIn(secret, encoded)
        self.assertEqual({path.name for path in self.destination.iterdir()},
                         {receipt["resourceId"][2:] + ".json" for receipt in self.receipts})

    def rotated_backup(self):
        old = self.base / "old.key"
        old.write_bytes(self.key)
        old.chmod(0o600)
        new = self.base / "active.key"
        new.write_bytes(os.urandom(32))
        new.chmod(0o600)
        prepared = credentials.prepare_rotation(self.vault.root, new_master_key_file=new,
                                                expected_receipts=self.receipts, master_key_file=old)
        credentials.activate_rotation(self.vault.root, prepared["generationId"])
        selected = self.vault.root / ".ava-custody-profile.json"
        source = credentials.open_vault(self.vault.root, self.authorize, credential_profile_file=selected)
        new_receipt = source.put(identifier(1), identifier(2), 1, identifier(8),
                                 b"Synthetic new-generation content", {"generation": 2})
        all_receipts = [*self.receipts, new_receipt]
        backup.create_backup(source, all_receipts, self.archive, self.backup_key, **self.actor)
        return source, new, all_receipts

    def later_profile_backups(self):
        old = self.base / "history-old.key"
        old.write_bytes(self.key)
        old.chmod(0o600)
        self.create()
        first = self.base / "history-first.key"
        first.write_bytes(os.urandom(32))
        first.chmod(0o600)
        prepared = credentials.prepare_rotation(self.vault.root, new_master_key_file=first,
                                                expected_receipts=self.receipts, master_key_file=old)
        credentials.activate_rotation(self.vault.root, prepared["generationId"])
        selector = self.vault.root / ".ava-custody-profile.json"
        selected = credentials.open_vault(self.vault.root, self.authorize, credential_profile_file=selector)
        newer = selected.put(identifier(1), identifier(2), 1, identifier(8),
                             b"Synthetic first-rotation content", {"generation": 1})
        receipts = [*self.receipts, newer]
        v2_archive = self.base / "history-v2.backup"
        backup.create_backup(selected, receipts, v2_archive, self.backup_key, **self.actor)
        current = self.base / "history-current.key"
        current.write_bytes(os.urandom(32))
        current.chmod(0o600)
        prepared = credentials.prepare_rotation(self.vault.root, new_master_key_file=current,
                                                expected_receipts=receipts, credential_profile_file=selector)
        credentials.activate_rotation(self.vault.root, prepared["generationId"])
        old.unlink()
        first.unlink()
        return selector, current, v2_archive, receipts

    def test_legacy_backup_restores_via_current_profile_after_two_rotations(self):
        selector, current, _, _ = self.later_profile_backups()
        result = backup.restore_backup(self.archive, self.destination, self.backup_key, current.read_bytes(),
                                       active_key_file=current, credential_profile_file=selector)
        self.assertEqual(result, self.receipts)
        restored = credentials.open_vault(self.destination, self.authorize,
                                           credential_profile_file=self.destination / ".ava-custody-profile.json")
        current_source = credentials.open_vault(self.vault.root, self.authorize, credential_profile_file=selector)
        for receipt in self.receipts:
            resource = receipt["resourceId"]
            self.assertEqual(restored.receipt(resource), receipt)
            self.assertEqual(restored.read(resource, **self.actor), current_source.read(resource, **self.actor))
            self.assertEqual((self.destination / (resource[2:] + ".json")).read_bytes(),
                             (self.vault.root / (resource[2:] + ".json")).read_bytes())
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            restored.read(self.receipts[0]["resourceId"], **self.actor)

    def test_rotated_backup_restores_via_profile_from_later_rotation(self):
        selector, current, v2_archive, receipts = self.later_profile_backups()
        result = backup.restore_backup(v2_archive, self.destination, self.backup_key, current.read_bytes(),
                                       active_key_file=current, credential_profile_file=selector)
        self.assertEqual(result, receipts)
        restored = credentials.open_vault(self.destination, self.authorize,
                                           credential_profile_file=self.destination / ".ava-custody-profile.json")
        current_source = credentials.open_vault(self.vault.root, self.authorize, credential_profile_file=selector)
        for receipt in receipts:
            resource = receipt["resourceId"]
            self.assertEqual(restored.receipt(resource), receipt)
            self.assertEqual(restored.read(resource, **self.actor), current_source.read(resource, **self.actor))
            self.assertEqual((self.destination / (resource[2:] + ".json")).read_bytes(),
                             (self.vault.root / (resource[2:] + ".json")).read_bytes())
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            restored.read(receipts[-1]["resourceId"], **self.actor)

    def test_current_profile_restore_rejects_foreign_keys_and_tampered_archive(self):
        selector, current, v2_archive, receipts = self.later_profile_backups()
        foreign_old = self.base / "foreign-old.key"
        foreign_old.write_bytes(os.urandom(32))
        foreign_old.chmod(0o600)
        foreign_active = self.base / "foreign-active.key"
        foreign_active.write_bytes(os.urandom(32))
        foreign_active.chmod(0o600)
        foreign_root = self.base / "foreign"
        credentials.open_vault(foreign_root, self.authorize, master_key_file=foreign_old)
        prepared = credentials.prepare_rotation(foreign_root, new_master_key_file=foreign_active,
                                                expected_receipts=[], master_key_file=foreign_old)
        credentials.activate_rotation(foreign_root, prepared["generationId"])
        foreign_selector = foreign_root / ".ava-custody-profile.json"
        for source in (self.archive, v2_archive):
            for key_bytes, key_file, profile_file in (
                    (foreign_active.read_bytes(), foreign_active, foreign_selector),
                    (foreign_active.read_bytes(), foreign_active, selector),
                    (current.read_bytes(), foreign_active, selector),
                    (current.read_bytes(), None, selector),
                    (current.read_bytes(), current, self.base / "missing-profile.json")):
                with self.subTest(source=source.name, key=key_file, profile=profile_file):
                    with self.assertRaises(backup.BackupError):
                        backup.restore_backup(source, self.destination, self.backup_key, key_bytes,
                                              active_key_file=key_file, credential_profile_file=profile_file)
                    self.assertFalse(self.destination.exists())
                    self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        original = v2_archive.read_bytes()
        magic = b"AVA-PRIVATE-BACKUP\x00\x02"
        nonce = original[len(magic):len(magic) + 12]
        package = json.loads(AESGCM(self.backup_key).decrypt(nonce, original[len(magic) + 12:], magic))
        sealed = bytearray(base64.b64decode(package["profile"]["sealedHistory"]))
        sealed[0] ^= 1
        package["profile"]["sealedHistory"] = base64.b64encode(sealed).decode()
        tampered = json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        v2_archive.write_bytes(magic + nonce + AESGCM(self.backup_key).encrypt(nonce, tampered, magic))
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(v2_archive, self.destination, self.backup_key, current.read_bytes(),
                                  active_key_file=current, credential_profile_file=selector)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        v2_archive.write_bytes(original)
        self.assertEqual(backup.restore_backup(v2_archive, self.destination, self.backup_key, current.read_bytes(),
                                               active_key_file=current, credential_profile_file=selector), receipts)

    def test_rotated_backup_restores_both_generations_with_current_authorization(self):
        source, new, all_receipts = self.rotated_backup()
        restored_receipts = backup.restore_backup(self.archive, self.destination, self.backup_key,
                                                 new.read_bytes(), active_key_file=new)
        self.assertEqual(restored_receipts, all_receipts)
        restored = credentials.open_vault(self.destination, self.authorize,
                                           credential_profile_file=self.destination / ".ava-custody-profile.json")
        for receipt in all_receipts:
            resource = receipt["resourceId"]
            self.assertEqual(restored.receipt(resource), receipt)
            self.assertEqual(restored.read(resource, **self.actor), source.read(resource, **self.actor))
            self.assertEqual((self.destination / (resource[2:] + ".json")).read_bytes(),
                             (self.vault.root / (resource[2:] + ".json")).read_bytes())
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            restored.read(all_receipts[-1]["resourceId"], **self.actor)
        encoded = self.archive.read_bytes()
        for secret in (self.key, new.read_bytes(), self.backup_key, self.payload, str(new).encode()):
            self.assertNotIn(secret, encoded)

    def test_rotated_restore_rejects_wrong_keys_tamper_and_partial_publication(self):
        _, new, receipts = self.rotated_backup()
        original = self.archive.read_bytes()
        other = self.base / "wrong.key"
        other.write_bytes(os.urandom(32))
        other.chmod(0o600)
        for kwargs in ({"backup_key": os.urandom(32)}, {"master_key": os.urandom(32)},
                       {"active_key_file": other}, {"active_key_file": None}):
            with self.subTest(kwargs=list(kwargs)):
                args = dict(backup_path=self.archive, destination=self.destination, backup_key=self.backup_key,
                            master_key=new.read_bytes(), active_key_file=new)
                args.update(kwargs)
                with self.assertRaises(backup.BackupError):
                    backup.restore_backup(**args)
                self.assertFalse(self.destination.exists())
                self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        for changed in (original[:-1], original[:15], original[:-1] + bytes([original[-1] ^ 1])):
            self.archive.write_bytes(changed)
            with self.assertRaises(backup.BackupError):
                backup.restore_backup(self.archive, self.destination, self.backup_key,
                                      new.read_bytes(), active_key_file=new)
            self.assertFalse(self.destination.exists())
            self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        self.archive.write_bytes(original)
        original_fsync = os.fsync
        parent_inode = self.base.stat().st_ino

        def fail_parent_sync(fd):
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode) and info.st_ino == parent_inode:
                raise OSError("synthetic commit failure")
            return original_fsync(fd)

        with mock.patch.object(backup.os, "fsync", side_effect=fail_parent_sync):
            with self.assertRaises(backup.BackupError):
                backup.restore_backup(self.archive, self.destination, self.backup_key,
                                      new.read_bytes(), active_key_file=new)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        self.assertEqual(backup.restore_backup(self.archive, self.destination, self.backup_key,
                                               new.read_bytes(), active_key_file=new), receipts)

    def test_authenticated_rotated_package_rejects_profile_tampering_without_staging(self):
        _, new, _ = self.rotated_backup()
        magic = b"AVA-PRIVATE-BACKUP\x00\x02"
        encoded = self.archive.read_bytes()
        self.assertTrue(encoded.startswith(magic))
        nonce = encoded[len(magic):len(magic) + 12]
        plaintext = AESGCM(self.backup_key).decrypt(nonce, encoded[len(magic) + 12:], magic)
        for secret in (self.key, new.read_bytes(), base64.b64encode(self.key),
                       base64.b64encode(new.read_bytes()), str(new).encode()):
            self.assertNotIn(secret, plaintext)
        original = json.loads(plaintext)
        for attack in ("invalid-ring", "missing-profile", "extra-profile-field"):
            package = json.loads(plaintext)
            if attack == "invalid-ring":
                raw = bytearray(base64.b64decode(package["profile"]["sealedHistory"]))
                raw[0] ^= 1
                package["profile"]["sealedHistory"] = base64.b64encode(raw).decode()
            elif attack == "missing-profile":
                package["profile"] = None
            else:
                package["profile"]["activeKeyFile"] = "unexpected"
            changed = json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
            new_nonce = os.urandom(12)
            self.archive.write_bytes(magic + new_nonce + AESGCM(self.backup_key).encrypt(new_nonce, changed, magic))
            with self.subTest(attack=attack), self.assertRaises(backup.BackupError):
                backup.restore_backup(self.archive, self.destination, self.backup_key,
                                      new.read_bytes(), active_key_file=new)
            self.assertFalse(self.destination.exists())
            self.assertEqual(list(self.base.glob(".ava-restore-*")), [])
        self.archive.write_bytes(encoded)
        self.assertEqual(original["version"], 2)

    def test_rotated_backup_contains_only_selected_records_and_requires_source_authorization(self):
        source, new, receipts = self.rotated_backup()
        subset = [receipts[0], receipts[-1]]
        subset_archive = self.base / "subset.backup"
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            backup.create_backup(source, subset, subset_archive, self.backup_key, **self.actor)
        self.assertFalse(subset_archive.exists())
        self.allowed = True
        backup.create_backup(source, subset, subset_archive, self.backup_key, **self.actor)
        self.assertEqual(backup.restore_backup(subset_archive, self.destination, self.backup_key,
                                               new.read_bytes(), active_key_file=new), subset)
        restored = credentials.open_vault(self.destination, self.authorize,
                                           credential_profile_file=self.destination / ".ava-custody-profile.json")
        for receipt in subset:
            self.assertEqual(restored.read(receipt["resourceId"], **self.actor),
                             source.read(receipt["resourceId"], **self.actor))
        with self.assertRaises(privacy.VaultError):
            restored.receipt(receipts[1]["resourceId"])

    def test_interrupted_restore_open_leaves_no_destination_or_staging_directory(self):
        self.create()
        original_open = os.open

        def fail_stage(path, *args, **kwargs):
            if str(path).startswith(".ava-restore-"):
                raise OSError("synthetic open failure")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(backup.os, "open", side_effect=fail_stage):
            with self.assertRaises(backup.BackupError):
                self.restore()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_source_backup_requires_current_read_authorization(self):
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            self.create()
        self.assertFalse(self.archive.exists())

    def test_restored_records_require_new_current_authorization_on_every_read(self):
        self.create()
        self.allowed = False
        self.assertEqual(self.restore(), self.receipts)
        restored = privacy.Vault(self.destination, self.key, self.authorize)
        resource = self.receipts[0]["resourceId"]
        with self.assertRaises(privacy.AccessDenied):
            restored.read(resource, **self.actor)
        self.allowed = True
        self.assertEqual(restored.read(resource, **self.actor), (self.payload, self.metadata))
        self.allowed = False
        with self.assertRaises(privacy.AccessDenied):
            restored.read(resource, **self.actor)

    def test_wrong_backup_or_vault_key_is_rejected_without_partial_destination(self):
        self.create()
        for overrides in ({"backup_key": os.urandom(32)}, {"master_key": os.urandom(32)}):
            with self.subTest(key=next(iter(overrides))):
                with self.assertRaises(backup.BackupError):
                    self.restore(**overrides)
                self.assertFalse(self.destination.exists())
                self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_tampered_or_truncated_encrypted_bundle_is_rejected(self):
        self.create()
        original = self.archive.read_bytes()
        for index in (0, 20, len(original) - 1):
            changed = bytearray(original)
            changed[index] ^= 1
            with self.subTest(index=index):
                self.archive.write_bytes(changed)
                with self.assertRaises(backup.BackupError):
                    self.restore()
                self.assertFalse(self.destination.exists())
        self.archive.write_bytes(original[:15])
        with self.assertRaises(backup.BackupError):
            self.restore()

    def test_existing_backup_or_destination_is_never_overwritten(self):
        self.create()
        original = self.archive.read_bytes()
        with self.assertRaises(backup.BackupError):
            self.create()
        self.assertEqual(self.archive.read_bytes(), original)
        for populated in (False, True):
            with self.subTest(populated=populated):
                self.destination.mkdir(mode=0o700)
                if populated:
                    (self.destination / "keep").write_bytes(b"existing data")
                with self.assertRaises(backup.BackupError):
                    self.restore()
                self.assertEqual({p.name for p in self.destination.iterdir()}, {"keep"} if populated else set())
                if populated:
                    self.assertEqual((self.destination / "keep").read_bytes(), b"existing data")
                    (self.destination / "keep").unlink()
                self.destination.rmdir()
                self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_unsafe_paths_symlinks_hardlinks_and_file_permissions_are_rejected(self):
        self.create()
        link = self.base / "linked-parent"
        link.symlink_to(self.base, target_is_directory=True)
        for destination in (link / "restored", self.base / ".." / "escape"):
            with self.subTest(path=destination):
                with self.assertRaises(backup.BackupError):
                    self.restore(destination=destination)
        self.destination.symlink_to(self.vault.root, target_is_directory=True)
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assertTrue(self.destination.is_symlink())
        self.destination.unlink()
        for source_kind in ("symlink", "hardlink", "permissions"):
            with self.subTest(source_kind=source_kind):
                other = self.base / "unsafe-backup"
                if source_kind == "symlink":
                    other.symlink_to(self.archive)
                elif source_kind == "hardlink":
                    os.link(self.archive, other)
                else:
                    other.write_bytes(self.archive.read_bytes())
                    other.chmod(0o644)
                with self.assertRaises(backup.BackupError):
                    self.restore(backup_path=other)
                other.unlink()
        with self.assertRaises(backup.BackupError):
            self.create(destination=link / "new-backup")
        self.assertFalse(self.destination.exists())

    def test_interrupted_commit_leaves_no_destination_or_staging_directory(self):
        self.create()
        original_fsync = os.fsync
        parent_inode = self.base.stat().st_ino

        def fail_parent_sync(fd):
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode) and info.st_ino == parent_inode:
                raise OSError("synthetic commit failure")
            return original_fsync(fd)

        with mock.patch.object(backup.os, "fsync", side_effect=fail_parent_sync):
            with self.assertRaises(backup.BackupError):
                self.restore()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_interrupted_backup_write_leaves_no_partial_file(self):
        with mock.patch.object(backup.os, "fsync", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(backup.BackupError):
                self.create()
        self.assertFalse(self.archive.exists())

    def rewrite_bundle(self, operation):
        # Exercise hostile authenticated input using the documented v1 wire
        # format and synthetic keys, without calling module internals.
        magic = b"AVA-PRIVATE-BACKUP\x00\x01"
        encoded = self.archive.read_bytes()
        nonce = encoded[len(magic):len(magic) + 12]
        package = json.loads(AESGCM(self.backup_key).decrypt(nonce, encoded[len(magic) + 12:], magic))
        operation(package)
        plaintext = json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        self.archive.write_bytes(magic + nonce + AESGCM(self.backup_key).encrypt(nonce, plaintext, magic))

    def test_authenticated_bundle_rejects_paths_duplicates_and_extra_files(self):
        self.create()
        original = self.archive.read_bytes()
        attacks = [lambda package: package["records"][0]["receipt"].__setitem__("resourceId", "../escape"),
                   lambda package: package["records"].append(package["records"][0]),
                   lambda package: package["records"][0].__setitem__("filename", "../escape"),
                   lambda package: package.__setitem__("credentials", {"bearer": "synthetic"})]
        for attack in attacks:
            self.archive.write_bytes(original)
            self.rewrite_bundle(attack)
            with self.assertRaises(backup.BackupError):
                self.restore()
            self.assertFalse(self.destination.exists())
            self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_bad_second_record_or_receipt_rolls_back_entire_restore(self):
        self.create()
        original = self.archive.read_bytes()
        attacks = [lambda package: package["records"][1].__setitem__("record", "e30="),
                   lambda package: package["records"][1]["receipt"].__setitem__("ciphertextHash", identifier(999)),
                   lambda package: package["records"][1]["receipt"].__setitem__("uri", "ava-private:v1:wrong")]
        for attack in attacks:
            self.archive.write_bytes(original)
            self.rewrite_bundle(attack)
            with self.assertRaises(backup.BackupError):
                self.restore()
            self.assertFalse(self.destination.exists())
            self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_invalid_or_mismatched_receipts_are_rejected_before_backup(self):
        mismatch = dict(self.receipts[0], caseId=identifier(999))
        for receipts in ([], self.receipts * 100, [self.receipts[0]] * 2,
                         [mismatch], [dict(self.receipts[0], master_key="forbidden")]):
            with self.subTest(count=len(receipts)):
                with self.assertRaises(backup.BackupError):
                    self.create(receipts=receipts)
                self.assertFalse(self.archive.exists())

    def test_recommitted_record_tampering_still_fails_vault_authentication(self):
        self.create()
        original = self.archive.read_bytes()
        for field in ("wrappedKey", "ciphertext", "wrapNonce", "dataNonce"):
            with self.subTest(field=field):
                self.archive.write_bytes(original)

                def tamper(package):
                    entry = package["records"][1]
                    record = json.loads(base64.b64decode(entry["record"]))
                    changed = bytearray(base64.b64decode(record[field]))
                    changed[0] ^= 1
                    record[field] = base64.b64encode(changed).decode()
                    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                    entry["record"] = base64.b64encode(encoded).decode()
                    entry["receipt"]["ciphertextHash"] = "0x" + hashlib.sha256(encoded).hexdigest()

                self.rewrite_bundle(tamper)
                with self.assertRaises(backup.BackupError):
                    self.restore()
                self.assertFalse(self.destination.exists())
                self.assertEqual(list(self.base.glob(".ava-restore-*")), [])

    def test_backup_size_and_key_bounds_are_enforced_without_destination(self):
        self.create()
        oversized = self.base / "oversized.backup"
        with oversized.open("wb") as stream:
            stream.truncate(backup.MAX_BACKUP_BYTES + 1)
        oversized.chmod(0o600)
        with self.assertRaises(backup.BackupError):
            self.restore(backup_path=oversized)
        for key in (b"short", bytearray(32), "x" * 32):
            with self.subTest(key_type=type(key).__name__):
                with self.assertRaises(backup.BackupError):
                    self.restore(backup_key=key)
                with self.assertRaises(backup.BackupError):
                    self.restore(master_key=key)
                with self.assertRaises(backup.BackupError):
                    self.create(destination=self.base / "invalid-key.backup", backup_key=key)
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.base / "invalid-key.backup").exists())


if __name__ == "__main__":
    unittest.main()
