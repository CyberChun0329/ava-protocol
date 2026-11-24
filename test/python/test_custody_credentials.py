import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import custody_credentials as credentials
from privacy_vault import VaultError, AccessDenied


def identifier(number):
    return '0x' + format(number, '064x')


class CustodyCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'vault'
        self.old = self.key('old')
        self.new = self.key('new')
        self.actor = {'persona': identifier(4), 'role': identifier(5), 'purpose': identifier(6)}
        self.allowed = True

    def key(self, name):
        path = self.base / name
        path.write_bytes(os.urandom(32))
        path.chmod(0o600)
        return path

    def authorize(self, *_):
        return self.allowed

    def put(self, vault, payload=b'private payload'):
        return vault.put(identifier(1), identifier(2), 1, identifier(3), payload, {'owner': 'private'})

    def test_open_requires_exactly_one_private_credential_and_keeps_legacy_behavior(self):
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize)
        vault = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(vault)
        self.assertEqual(vault.read(receipt['resourceId'], **self.actor), (b'private payload', {'owner': 'private'}))
        self.allowed = False
        with self.assertRaises(AccessDenied):
            vault.read(receipt['resourceId'], **self.actor)


    def test_rotation_keeps_old_records_and_receipts_and_new_writes_use_new_key(self):
        from privacy_vault import Vault
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        original = (self.root / (receipt['resourceId'][2:] + '.json')).read_bytes()
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        self.assertEqual(legacy.read(receipt['resourceId'], **self.actor)[0], b'private payload')
        credentials.activate_rotation(self.root, prepared['generationId'])
        with self.assertRaises(VaultError):
            Vault(self.root, self.old.read_bytes(), self.authorize)
        current = credentials.open_vault(self.root, self.authorize,
            credential_profile_file=self.root / '.ava-custody-profile.json')
        self.assertEqual(current.receipt(receipt['resourceId']), receipt)
        self.assertEqual(current.read(receipt['resourceId'], **self.actor), (b'private payload', {'owner': 'private'}))
        self.assertEqual((self.root / (receipt['resourceId'][2:] + '.json')).read_bytes(), original)
        new_receipt = self.put(current, b'after rotation')
        copy = self.base / 'independent-control'
        copy.mkdir(mode=0o700)
        record = self.root / (new_receipt['resourceId'][2:] + '.json')
        (copy / record.name).write_bytes(record.read_bytes())
        (copy / record.name).chmod(0o600)
        with self.assertRaises(VaultError):
            Vault(copy, self.old.read_bytes(), self.authorize).read(new_receipt['resourceId'], **self.actor)
        self.assertEqual(Vault(copy, self.new.read_bytes(), self.authorize).read(new_receipt['resourceId'], **self.actor)[0], b'after rotation')
        self.allowed = False
        with self.assertRaises(AccessDenied):
            current.read(receipt['resourceId'], **self.actor)


    def test_missing_selector_never_falls_back_and_current_denial_stays_first(self):
        from privacy_vault import Vault
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        saved = selector.read_bytes()
        selector.unlink()
        with self.assertRaises(VaultError):
            Vault(self.root, self.old.read_bytes(), self.authorize)
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        self.allowed = False
        with self.assertRaises(AccessDenied):
            current.read(receipt['resourceId'], **self.actor)
        self.allowed = True
        with self.assertRaises(VaultError):
            current.read(receipt['resourceId'], **self.actor)
        selector.write_bytes(saved)
        selector.chmod(0o600)
        self.assertEqual(current.read(receipt['resourceId'], **self.actor)[0], b'private payload')


    def test_twice_rotation_retains_orphans_and_rejects_stale_or_reused_generations(self):
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt, orphan = self.put(legacy), self.put(legacy, b'orphan')
        p1 = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        self.assertEqual(p1['recordCount'], 2)
        late = self.put(legacy, b'late')
        with self.assertRaises(VaultError):
            credentials.activate_rotation(self.root, p1['generationId'])
        self.assertEqual(credentials.inspect_credentials(self.root), {'mode': 'legacy'})
        (self.root / (late['resourceId'][2:] + '.json')).unlink()
        credentials.activate_rotation(self.root, p1['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        second = self.put(current, b'written after first')
        with self.assertRaises(VaultError):
            credentials.prepare_rotation(self.root, new_master_key_file=self.old,
                expected_receipts=[receipt, second], credential_profile_file=selector)
        third_key = self.key('third')
        p2 = credentials.prepare_rotation(self.root, new_master_key_file=third_key,
            expected_receipts=[receipt, second], credential_profile_file=selector)
        credentials.activate_rotation(self.root, p2['generationId'])
        self.old.unlink()
        self.new.unlink()
        final = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        self.assertEqual(final.read(receipt['resourceId'], **self.actor)[0], b'private payload')
        self.assertEqual(final.read(orphan['resourceId'], **self.actor)[0], b'orphan')
        self.assertEqual(final.read(second['resourceId'], **self.actor)[0], b'written after first')
        with self.assertRaises(VaultError):
            credentials.activate_rotation(self.root, p1['generationId'])
        with self.assertRaises(VaultError):
            current.read(receipt['resourceId'], **self.actor)
        self.assertEqual(credentials.inspect_credentials(self.root)['keyCount'], 3)


    def test_portable_profile_reconstructs_in_fresh_root_and_rejects_wrong_key(self):
        import json
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        portable = credentials.portable_profile(current)
        raw = json.dumps(portable)
        self.assertNotIn(str(self.base), raw)
        self.assertNotIn(self.old.read_bytes().hex(), raw)
        self.assertNotIn(self.new.read_bytes().hex(), raw)
        destination = self.base / 'restored'
        destination.mkdir(mode=0o700)
        record = self.root / (receipt['resourceId'][2:] + '.json')
        (destination / record.name).write_bytes(record.read_bytes())
        (destination / record.name).chmod(0o600)
        with self.assertRaises(VaultError):
            credentials.install_portable_profile(destination, portable, self.old)
        self.assertFalse((destination / '.ava-custody-profile.json').exists())
        credentials.install_portable_profile(destination, portable, self.new)
        restored = credentials.open_vault(destination, self.authorize,
            credential_profile_file=destination / '.ava-custody-profile.json')
        self.assertEqual(credentials.portable_profile(restored), portable)
        self.assertEqual(restored.receipt(receipt['resourceId']), receipt)
        self.assertEqual(restored.read(receipt['resourceId'], **self.actor)[0], b'private payload')
        self.allowed = False
        with self.assertRaises(AccessDenied):
            restored.read(receipt['resourceId'], **self.actor)

    def test_interrupted_activation_is_closed_and_can_continue(self):
        from unittest import mock
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        with mock.patch.object(credentials.os, 'replace', side_effect=OSError('modeled interruption')):
            with self.assertRaises(VaultError):
                credentials.activate_rotation(self.root, prepared['generationId'])
        self.assertEqual(credentials.inspect_credentials(self.root), {
            'mode': 'activation_incomplete', 'candidateGenerationIds': [prepared['generationId']]})
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        activated = credentials.activate_rotation(self.root, prepared['generationId'])
        self.assertEqual(credentials.activate_rotation(self.root, prepared['generationId']), activated)
        current = credentials.open_vault(self.root, self.authorize,
            credential_profile_file=self.root / '.ava-custody-profile.json')
        self.assertEqual(current.read(receipt['resourceId'], **self.actor)[0], b'private payload')

    def test_key_durability_failure_does_not_select_a_generation(self):
        from unittest import mock
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        with mock.patch.object(credentials.os, 'fsync', side_effect=OSError('modeled fsync failure')):
            with self.assertRaises(VaultError):
                credentials.prepare_rotation(self.root, new_master_key_file=self.new,
                    expected_receipts=[receipt], master_key_file=self.old)
        self.assertEqual(credentials.inspect_credentials(self.root), {'mode': 'legacy'})
        self.assertEqual(legacy.read(receipt['resourceId'], **self.actor)[0], b'private payload')

    def test_missing_and_conflicting_receipts_and_damaged_history_fail_closed(self):
        import json
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        conflict = dict(receipt, ciphertextHash='0x' + 'a' * 64)
        for receipts in ([conflict], [receipt, receipt], [dict(receipt, resourceId=identifier(99))]):
            with self.assertRaises(VaultError):
                credentials.prepare_rotation(self.root, new_master_key_file=self.new,
                    expected_receipts=receipts, master_key_file=self.old)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        generation = self.root / '.ava-credentials' / prepared['generationId'] / 'generation.json'
        before = generation.read_bytes()
        changed = json.loads(before)
        changed['sealedHistory'] = changed['sealedHistory'][:-4] + 'AAAA'
        generation.write_text(json.dumps(changed, sort_keys=True, separators=(',', ':')))
        with self.assertRaises(VaultError):
            current.read(receipt['resourceId'], **self.actor)
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        generation.write_bytes(before)
        self.assertEqual(current.read(receipt['resourceId'], **self.actor)[0], b'private payload')

    def test_key_capacity_never_discards_history(self):
        credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        selected = None
        for index in range(1, 32):
            key = self.key('capacity-' + str(index))
            kwargs = {'master_key_file': self.old} if selected is None else {'credential_profile_file': self.root / '.ava-custody-profile.json'}
            prepared = credentials.prepare_rotation(self.root, new_master_key_file=key, expected_receipts=[], **kwargs)
            selected = credentials.activate_rotation(self.root, prepared['generationId'])
        self.assertEqual(selected['keyCount'], 32)
        with self.assertRaises(VaultError):
            credentials.prepare_rotation(self.root, new_master_key_file=self.key('too-many'), expected_receipts=[],
                credential_profile_file=self.root / '.ava-custody-profile.json')
        self.assertEqual(credentials.inspect_credentials(self.root), selected)


    def test_active_key_and_selector_are_revalidated_for_each_operation(self):
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        original = self.new.read_bytes()
        self.new.write_bytes(os.urandom(32))
        with self.assertRaises(VaultError):
            current.put(identifier(1), identifier(2), 1, identifier(3), b'x', {})
        self.allowed = False
        with self.assertRaises(AccessDenied):
            current.read(receipt['resourceId'], **self.actor)
        self.allowed = True
        with self.assertRaises(VaultError):
            current.read(receipt['resourceId'], **self.actor)
        self.new.write_bytes(original)
        self.new.chmod(0o644)
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        self.new.chmod(0o600)
        with self.assertRaises(VaultError):
            credentials.open_vault(self.root, self.authorize, credential_profile_file=self.root / 'other.json')
        self.assertEqual(current.read(receipt['resourceId'], **self.actor)[0], b'private payload')

    def test_corrupt_orphan_also_prevents_rotation(self):
        import json
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt, orphan = self.put(legacy), self.put(legacy, b'orphan')
        path = self.root / (orphan['resourceId'][2:] + '.json')
        record = json.loads(path.read_bytes())
        value = record['ciphertext']
        record['ciphertext'] = ('A' if value[0] != 'A' else 'B') + value[1:]
        path.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')))
        with self.assertRaises(VaultError):
            credentials.prepare_rotation(self.root, new_master_key_file=self.new,
                expected_receipts=[receipt], master_key_file=self.old)
        self.assertEqual(credentials.inspect_credentials(self.root), {'mode': 'legacy'})


    def test_foreign_portable_cannot_take_over_existing_legacy_material(self):
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        foreign_root = self.base / 'foreign'
        foreign = credentials.open_vault(foreign_root, self.authorize, master_key_file=self.new)
        foreign_receipt = self.put(foreign, b'foreign')
        foreign_active = self.key('foreign-active')
        prepared = credentials.prepare_rotation(foreign_root, new_master_key_file=foreign_active,
            expected_receipts=[foreign_receipt], master_key_file=self.new)
        credentials.activate_rotation(foreign_root, prepared['generationId'])
        profile = credentials.portable_profile(credentials.open_vault(foreign_root, self.authorize,
            credential_profile_file=foreign_root / '.ava-custody-profile.json'))
        with self.assertRaises(VaultError):
            credentials.install_portable_profile(self.root, profile, foreign_active)
        self.assertEqual(credentials.inspect_credentials(self.root), {'mode': 'legacy'})
        self.assertEqual(legacy.read(receipt['resourceId'], **self.actor)[0], b'private payload')
        self.assertFalse((self.root / '.ava-credentials').exists())
        legitimate = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, legitimate['generationId'])
        managed = credentials.open_vault(self.root, self.authorize,
            credential_profile_file=self.root / '.ava-custody-profile.json')
        self.assertEqual(managed.read(receipt['resourceId'], **self.actor)[0], b'private payload')


    def test_archived_profile_authenticates_via_current_history_without_grants(self):
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        first = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, first['generationId'])
        selector = self.root / '.ava-custody-profile.json'
        first_vault = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        archived = credentials.portable_profile(first_vault)
        third = self.key('archive-current')
        second = credentials.prepare_rotation(self.root, new_master_key_file=third,
            expected_receipts=[receipt], credential_profile_file=selector)
        credentials.activate_rotation(self.root, second['generationId'])
        incomplete = credentials.open_vault(self.base / 'incomplete-history', self.authorize, master_key_file=self.new)
        with self.assertRaises(VaultError):
            credentials.authenticate_portable_profile(archived, incomplete)
        self.old.unlink()
        self.new.unlink()
        current = credentials.open_vault(self.root, self.authorize, credential_profile_file=selector)
        self.assertIsNone(credentials.authenticate_portable_profile(archived, current))
        damaged = dict(archived, sealedHistory=archived['sealedHistory'][:-4] + 'AAAA')
        with self.assertRaises(VaultError):
            credentials.authenticate_portable_profile(damaged, current)
        unrelated_root = self.base / 'unrelated'
        unrelated_key = self.key('unrelated-key')
        unrelated = credentials.open_vault(unrelated_root, self.authorize, master_key_file=unrelated_key)
        with self.assertRaises(VaultError):
            credentials.authenticate_portable_profile(archived, unrelated)
        self.allowed = False
        self.assertIsNone(credentials.authenticate_portable_profile(archived, current))
        with self.assertRaises(AccessDenied):
            current.read(receipt['resourceId'], **self.actor)
        third.write_bytes(os.urandom(32))
        with self.assertRaises(VaultError):
            credentials.authenticate_portable_profile(archived, current)


    def test_portable_install_rejects_corrupt_or_disappearing_records_and_allows_empty_root(self):
        import json
        from unittest import mock
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        receipt = self.put(legacy)
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[receipt], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        source = credentials.open_vault(self.root, self.authorize,
            credential_profile_file=self.root / '.ava-custody-profile.json')
        portable = credentials.portable_profile(source)
        name = receipt['resourceId'][2:] + '.json'
        original = (self.root / name).read_bytes()
        destination = self.base / 'bad-restore'
        destination.mkdir(mode=0o700)
        path = destination / name
        record = json.loads(original)
        text = record['ciphertext']
        record['ciphertext'] = ('A' if text[0] != 'A' else 'B') + text[1:]
        path.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')))
        path.chmod(0o600)
        with self.assertRaises(VaultError):
            credentials.install_portable_profile(destination, portable, self.new)
        self.assertEqual(credentials.inspect_credentials(destination), {'mode': 'legacy'})
        self.assertFalse((destination / '.ava-credentials').exists())
        path.write_bytes(original)
        real_listdir = os.listdir
        def remove_after_listing(directory):
            names = real_listdir(directory)
            if Path(directory) == destination and name in names:
                path.unlink()
            return names
        with mock.patch.object(credentials.os, 'listdir', side_effect=remove_after_listing):
            with self.assertRaises(VaultError):
                credentials.install_portable_profile(destination, portable, self.new)
        self.assertEqual(credentials.inspect_credentials(destination), {'mode': 'legacy'})
        path.write_bytes(original)
        path.chmod(0o600)
        control = credentials.open_vault(destination, self.authorize, master_key_file=self.old)
        self.assertEqual(control.read(receipt['resourceId'], **self.actor)[0], b'private payload')
        empty = self.base / 'empty-restore'
        empty.mkdir(mode=0o700)
        installed = credentials.install_portable_profile(empty, portable, self.new)
        self.assertEqual(installed['generationId'], prepared['generationId'])
        self.assertEqual(credentials.portable_profile(credentials.open_vault(empty, self.authorize,
            credential_profile_file=empty / '.ava-custody-profile.json')), portable)

    def test_portable_install_rechecks_inventory_before_publication(self):
        from unittest import mock
        legacy = credentials.open_vault(self.root, self.authorize, master_key_file=self.old)
        first, second = self.put(legacy), self.put(legacy, b'late record')
        prepared = credentials.prepare_rotation(self.root, new_master_key_file=self.new,
            expected_receipts=[first, second], master_key_file=self.old)
        credentials.activate_rotation(self.root, prepared['generationId'])
        source = credentials.open_vault(self.root, self.authorize,
            credential_profile_file=self.root / '.ava-custody-profile.json')
        portable = credentials.portable_profile(source)
        destination = self.base / 'changed-restore'
        destination.mkdir(mode=0o700)
        first_name = first['resourceId'][2:] + '.json'
        second_name = second['resourceId'][2:] + '.json'
        (destination / first_name).write_bytes((self.root / first_name).read_bytes())
        (destination / first_name).chmod(0o600)
        late_bytes = (self.root / second_name).read_bytes()
        original_fsync = os.fsync
        inserted = False
        def add_record(fd):
            nonlocal inserted
            if not inserted:
                inserted = True
                (destination / second_name).write_bytes(late_bytes)
                (destination / second_name).chmod(0o600)
            return original_fsync(fd)
        with mock.patch.object(credentials.os, 'fsync', side_effect=add_record):
            with self.assertRaises(VaultError):
                credentials.install_portable_profile(destination, portable, self.new)
        self.assertTrue(inserted)
        self.assertEqual(credentials.inspect_credentials(destination), {'mode': 'legacy'})
        control = credentials.open_vault(destination, self.authorize, master_key_file=self.old)
        self.assertEqual(control.read(first['resourceId'], **self.actor)[0], b'private payload')
        self.assertEqual(control.read(second['resourceId'], **self.actor)[0], b'late record')


if __name__ == '__main__':
    unittest.main()
