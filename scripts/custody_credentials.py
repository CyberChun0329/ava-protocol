"""Stopped-operator credential generations for the generic encrypted Vault.

The caller must stop all Vault writers throughout prepare and activation. This
module stores no plaintext key and grants no authority to read material.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from private_files import ROOT, private_bytes, project_path
from privacy_vault import Vault, VaultError, _json, _parse

SELECTOR = '.ava-custody-profile.json'
GENERATIONS = '.ava-credentials'
MANAGED = '.ava-custody-managed'
_MARKER = b'ava-custody-managed:v1\n'
MAX_KEYS = 32
_ID = re.compile(r'[0-9a-f]{32}\Z')
_RECORD = re.compile(r'[0-9a-f]{64}\.json\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_RECEIPT_FIELDS = {'resourceId', 'appId', 'caseId', 'policyId', 'materialClass', 'ciphertextHash', 'uri'}


def _path(value):
    try:
        return project_path(value)
    except (OSError, ValueError, TypeError):
        raise VaultError('Invalid custody path') from None


def _key_file(path):
    try:
        key = private_bytes(path, 32)
        if len(key) != 32:
            raise ValueError()
        return key
    except (OSError, ValueError, TypeError):
        raise VaultError('Invalid private credential file') from None


def _private_dir(path):
    try:
        path = _path(path)
        info = path.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError()
        return path
    except (OSError, ValueError):
        raise VaultError('Unsafe credential directory') from None


def _read(path, limit):
    try:
        data = private_bytes(path, limit)
        if len(data) > limit:
            raise ValueError()
        return data
    except (OSError, ValueError, TypeError):
        raise VaultError('Credential material unavailable or unsafe') from None


def _object(data):
    obj = _parse(data)
    if type(obj) is not dict or _json(obj) != data:
        raise VaultError('Invalid credential material')
    return obj


def _write(path, data):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise VaultError('Credential write failed') from None


def _sync(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise VaultError('Credential durability failed') from None


def _sync_key(path, expected):
    try:
        fd = os.open(_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 32
                    or os.read(fd, 33) != expected):
                raise VaultError('Invalid private credential file')
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync(_path(path).parent)
    except OSError:
        raise VaultError('Credential durability failed') from None


def _present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        raise VaultError('Credential material unavailable') from None


def _selector(root):
    path = root / SELECTOR
    if not _present(path):
        return None, None
    encoded = _read(path, 4096)
    if _read(root / MANAGED, 64) != _MARKER:
        raise VaultError('Invalid managed vault marker')
    value = _object(encoded)
    if (set(value) != {'version', 'generationId', 'generationHash'} or value['version'] != 1
            or type(value['version']) is not int or type(value['generationId']) is not str
            or not _ID.fullmatch(value['generationId']) or type(value['generationHash']) is not str
            or not _HASH.fullmatch(value['generationHash'])):
        raise VaultError('Invalid credential selector')
    return value, encoded


def _generation_dir(root, generation_id):
    if type(generation_id) is not str or not _ID.fullmatch(generation_id):
        raise VaultError('Invalid credential generation')
    _private_dir(root / GENERATIONS)
    return _private_dir(root / GENERATIONS / generation_id)


def _key_id(key):
    return hashlib.sha256(key).hexdigest()


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _unb64(value, size=None):
    try:
        if type(value) is not str or len(value) > 4096:
            raise ValueError()
        result = base64.b64decode(value, validate=True)
        if _b64(result) != value or (size is not None and len(result) != size):
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise VaultError('Invalid sealed credential history') from None


def _aad(value):
    return b'ava-custody-history:v1\0' + _json({key: value[key] for key in ('version', 'generationId', 'keyIds', 'manifestHash')})


def _validate_portable(value, active):
    if (type(value) is not dict or set(value) != {'version', 'generationId', 'keyIds', 'manifestHash', 'nonce', 'sealedHistory'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['generationId']) is not str or not _ID.fullmatch(value['generationId'])
            or type(value['manifestHash']) is not str or not _HASH.fullmatch(value['manifestHash'])
            or type(value['keyIds']) is not list or not 1 <= len(value['keyIds']) <= MAX_KEYS
            or any(type(item) is not str or not _HASH.fullmatch(item) for item in value['keyIds'])
            or len(set(value['keyIds'])) != len(value['keyIds']) or value['keyIds'][0] != _key_id(active)):
        raise VaultError('Invalid credential profile')
    nonce, sealed = _unb64(value['nonce'], 12), _unb64(value['sealedHistory'])
    if len(sealed) != 16 + 32 * (len(value['keyIds']) - 1):
        raise VaultError('Invalid credential history size')
    try:
        history = AESGCM(active).decrypt(nonce, sealed, _aad(value))
    except (InvalidTag, ValueError):
        raise VaultError('Credential authentication failed') from None
    keys = (active,) + tuple(history[i:i + 32] for i in range(0, len(history), 32))
    if [_key_id(key) for key in keys] != value['keyIds']:
        raise VaultError('Credential history mismatch')
    return keys


def _load_generation(root, generation_id, expected_hash=None):
    directory = _generation_dir(root, generation_id)
    encoded = _read(directory / 'generation.json', 16384)
    if expected_hash is not None and hashlib.sha256(encoded).hexdigest() != expected_hash:
        raise VaultError('Credential generation mismatch')
    value = _object(encoded)
    if set(value) != {'version', 'generationId', 'keyIds', 'manifestHash', 'nonce', 'sealedHistory', 'activeKeyFile'}:
        raise VaultError('Invalid credential generation')
    if value['generationId'] != generation_id or type(value['activeKeyFile']) is not str:
        raise VaultError('Invalid credential generation')
    active_path = Path(value['activeKeyFile'])
    if active_path.is_absolute() or '..' in active_path.parts:
        raise VaultError('Invalid credential file reference')
    active = _key_file(active_path)
    portable = {key: value[key] for key in ('version', 'generationId', 'keyIds', 'manifestHash', 'nonce', 'sealedHistory')}
    keys = _validate_portable(portable, active)
    return value, encoded, keys


class _CredentialState:
    def __init__(self, root, selector, encoded, keys):
        self.root, self.selector, self.encoded, self.keys = root, selector, encoded, keys

    def validate(self):
        _private_dir(self.root)
        current, current_bytes = _selector(self.root)
        if current != self.selector or current_bytes is None:
            raise VaultError('Selected credential generation changed')
        _, encoded, keys = _load_generation(self.root, current['generationId'], current['generationHash'])
        if encoded != self.encoded or keys != self.keys:
            raise VaultError('Selected credential generation changed')


class _UnselectedState:
    def __init__(self, root, keys):
        self.root, self.keys = root, keys

    def validate(self):
        if _selector(self.root)[0] is not None:
            raise VaultError('Credential baseline changed')


def open_vault(root, authorizer, *, master_key_file=None, credential_profile_file=None):
    if (master_key_file is None) == (credential_profile_file is None):
        raise VaultError('Exactly one custody credential is required')
    root = _path(root)
    if credential_profile_file is None:
        return Vault(root, _key_file(master_key_file), authorizer)
    if _path(credential_profile_file) != root / SELECTOR:
        raise VaultError('Credential profile must be the vault selector')
    _private_dir(root)
    selector, _ = _selector(root)
    if selector is None:
        raise VaultError('Credential profile unavailable')
    _, encoded, keys = _load_generation(root, selector['generationId'], selector['generationHash'])
    return Vault(root, keys[0], authorizer, _credential_state=_CredentialState(root, selector, encoded, keys))


def _inventory(vault, keys, expected_receipts):
    vault._check_credentials()
    expected = {}
    if type(expected_receipts) is not list:
        raise VaultError('Expected receipts must be a complete list')
    for receipt in expected_receipts:
        if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS or type(receipt.get('resourceId')) is not str:
            raise VaultError('Invalid expected receipt')
        resource = receipt['resourceId']
        if resource in expected:
            raise VaultError('Duplicate expected receipt')
        expected[resource] = receipt
    inventory = {}
    try:
        names = os.listdir(vault.root)
    except OSError:
        raise VaultError('Vault inventory unavailable') from None
    for name in names:
        if name in (SELECTOR, GENERATIONS, MANAGED):
            continue
        if re.fullmatch(r'\.ava-selector-[0-9a-f]{32}', name):
            _read(vault.root / name, 4096)
            continue
        if not _RECORD.fullmatch(name):
            raise VaultError('Unexpected vault inventory entry')
        resource = '0x' + name[:-5]
        record, encoded = vault._load(resource)
        receipt = vault._receipt(record, encoded)
        if resource in expected and expected[resource] != receipt:
            raise VaultError('Expected receipt mismatch')
        Vault._decrypt_record(record, keys)
        inventory[resource] = hashlib.sha256(encoded).hexdigest()
    if not set(expected).issubset(inventory):
        raise VaultError('Expected receipt unavailable')
    return dict(sorted(inventory.items()))


def _mkdir(path):
    try:
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
    except OSError:
        raise VaultError('Cannot create credential generation') from None


def prepare_rotation(root, *, new_master_key_file, expected_receipts, master_key_file=None, credential_profile_file=None):
    root = _path(root)
    vault = open_vault(root, lambda *_: False, master_key_file=master_key_file, credential_profile_file=credential_profile_file)
    old_keys = vault._credential_state.keys if vault._credential_state else (vault._master_key,)
    active_path = _path(new_master_key_file)
    new_key = _key_file(active_path)
    if new_key in old_keys or len(old_keys) >= MAX_KEYS:
        raise VaultError('Reused key or credential capacity exceeded')
    _sync_key(active_path, new_key)
    keys = (new_key,) + tuple(old_keys)
    inventory = _inventory(vault, keys, expected_receipts)
    _, selector_bytes = _selector(root)
    manifest = {'version': 1, 'baseline': hashlib.sha256(selector_bytes).hexdigest() if selector_bytes is not None else None,
                'inventory': inventory, 'expectedReceipts': expected_receipts}
    manifest_bytes = _json(manifest)
    generation_id = os.urandom(16).hex()
    parent = root / GENERATIONS
    if not _present(parent):
        _mkdir(parent)
        _sync(root)
    _private_dir(parent)
    directory = parent / generation_id
    _mkdir(directory)
    nonce = os.urandom(12)
    portable = {'version': 1, 'generationId': generation_id, 'keyIds': [_key_id(key) for key in keys],
                'manifestHash': hashlib.sha256(manifest_bytes).hexdigest(), 'nonce': _b64(nonce)}
    portable['sealedHistory'] = _b64(AESGCM(new_key).encrypt(nonce, b''.join(old_keys), _aad(portable)))
    generation = dict(portable, activeKeyFile=str(active_path.relative_to(ROOT)))
    generation_bytes = _json(generation)
    _write(directory / 'manifest.json', manifest_bytes)
    _write(directory / 'generation.json', generation_bytes)
    _sync(directory)
    _sync(parent)
    _load_generation(root, generation_id, hashlib.sha256(generation_bytes).hexdigest())
    return {'mode': 'prepared', 'generationId': generation_id, 'keyCount': len(keys), 'recordCount': len(inventory),
            'expectedReceiptCount': len(expected_receipts)}


def activate_rotation(root, generation_id):
    root = _private_dir(_path(root))
    current, current_bytes = _selector(root)
    if current is not None and current['generationId'] == generation_id:
        _, _, keys = _load_generation(root, generation_id, current['generationHash'])
        return {'mode': 'profile', 'generationId': generation_id, 'keyCount': len(keys)}
    generation, encoded, keys = _load_generation(root, generation_id)
    manifest_bytes = _read(_generation_dir(root, generation_id) / 'manifest.json', 64 * 1024 * 1024)
    if hashlib.sha256(manifest_bytes).hexdigest() != generation['manifestHash']:
        raise VaultError('Credential preparation mismatch')
    manifest = _object(manifest_bytes)
    if (set(manifest) != {'version', 'baseline', 'inventory', 'expectedReceipts'} or manifest['version'] != 1
            or type(manifest['version']) is not int or type(manifest['inventory']) is not dict):
        raise VaultError('Invalid credential preparation')
    baseline = hashlib.sha256(current_bytes).hexdigest() if current_bytes is not None else None
    if baseline != manifest['baseline']:
        raise VaultError('Credential baseline changed')
    if current is None:
        if _present(root / MANAGED):
            if _read(root / MANAGED, 64) != _MARKER:
                raise VaultError('Invalid managed vault marker')
            vault = Vault(root, keys[0], lambda *_: False, _credential_state=_UnselectedState(root, keys))
        else:
            vault = Vault(root, keys[1], lambda *_: False)
    else:
        vault = open_vault(root, lambda *_: False, credential_profile_file=root / SELECTOR)
    if _inventory(vault, keys, manifest['expectedReceipts']) != manifest['inventory']:
        raise VaultError('Vault inventory changed')
    _sync_key(generation['activeKeyFile'], keys[0])
    if not _present(root / MANAGED):
        _write(root / MANAGED, _MARKER)
        _sync(root)
    selector = {'version': 1, 'generationId': generation_id, 'generationHash': hashlib.sha256(encoded).hexdigest()}
    temp = root / ('.ava-selector-' + os.urandom(16).hex())
    _write(temp, _json(selector))
    try:
        os.replace(temp, root / SELECTOR)
        _sync(root)
    except OSError:
        raise VaultError('Credential activation failed; inspect selector') from None
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    return {'mode': 'profile', 'generationId': generation_id, 'keyCount': len(keys)}


def inspect_credentials(root):
    root = _private_dir(_path(root))
    selector, _ = _selector(root)
    if selector is None:
        if _present(root / MANAGED):
            if _read(root / MANAGED, 64) != _MARKER:
                raise VaultError('Invalid managed vault marker')
            parent = _private_dir(root / GENERATIONS)
            try:
                names = sorted(os.listdir(parent))
            except OSError:
                raise VaultError('Credential generations unavailable') from None
            candidates = []
            for name in names:
                if not _ID.fullmatch(name):
                    continue
                try:
                    generation, _, keys = _load_generation(root, name)
                    data = _read(_generation_dir(root, name) / 'manifest.json', 64 * 1024 * 1024)
                    manifest = _object(data)
                    if (hashlib.sha256(data).hexdigest() != generation['manifestHash']
                            or set(manifest) != {'version', 'baseline', 'inventory', 'expectedReceipts'}
                            or type(manifest['version']) is not int or manifest['version'] != 1
                            or manifest['baseline'] is not None or type(manifest['inventory']) is not dict):
                        continue
                    verifier = Vault(root, keys[0], lambda *_: False, _credential_state=_UnselectedState(root, keys))
                    if _inventory(verifier, keys, manifest['expectedReceipts']) == manifest['inventory']:
                        candidates.append(name)
                except VaultError:
                    continue
                if len(candidates) > 128:
                    raise VaultError('Too many incomplete activation candidates')
            return {'mode': 'activation_incomplete', 'candidateGenerationIds': candidates}
        return {'mode': 'legacy'}
    _, _, keys = _load_generation(root, selector['generationId'], selector['generationHash'])
    return {'mode': 'profile', 'generationId': selector['generationId'], 'keyCount': len(keys)}


def portable_profile(vault):
    vault._check_credentials()
    if vault._credential_state is None:
        return None
    value, _, _ = _load_generation(vault.root, vault._credential_state.selector['generationId'], vault._credential_state.selector['generationHash'])
    return {key: value[key] for key in ('version', 'generationId', 'keyIds', 'manifestHash', 'nonce', 'sealedHistory')}


def authenticate_portable_profile(portable, vault):
    """Authenticate archived history against retained keys without granting access."""
    vault._check_credentials()
    keys = vault._credential_state.keys if vault._credential_state is not None else (vault._master_key,)
    if (type(portable) is not dict or type(portable.get('keyIds')) is not list
            or not portable['keyIds'] or type(portable['keyIds'][0]) is not str):
        raise VaultError('Invalid credential profile')
    active = next((key for key in keys if _key_id(key) == portable['keyIds'][0]), None)
    if active is None:
        raise VaultError('Archived credential is not retained')
    archived_keys = _validate_portable(portable, active)
    if any(key not in keys for key in archived_keys):
        raise VaultError('Archived credential history is not retained')


def install_portable_profile(root, portable, active_key_file):
    root = _private_dir(_path(root))
    if _present(root / SELECTOR) or _present(root / GENERATIONS) or _present(root / MANAGED):
        raise VaultError('Destination already has credentials')
    active_path = _path(active_key_file)
    keys = _validate_portable(portable, _key_file(active_path))
    verifier = Vault(root, keys[0], lambda *_: False, _credential_state=_UnselectedState(root, keys))
    inventory = _inventory(verifier, keys, [])
    _sync_key(active_path, keys[0])
    parent = root / GENERATIONS
    _mkdir(parent)
    directory = parent / portable['generationId']
    _mkdir(directory)
    encoded = _json(dict(portable, activeKeyFile=str(active_path.relative_to(ROOT))))
    _write(directory / 'generation.json', encoded)
    _sync(directory)
    _sync(parent)
    if _inventory(verifier, keys, []) != inventory:
        raise VaultError('Vault inventory changed')
    selector = {'version': 1, 'generationId': portable['generationId'], 'generationHash': hashlib.sha256(encoded).hexdigest()}
    _write(root / MANAGED, _MARKER)
    _sync(root)
    _write(root / SELECTOR, _json(selector))
    _sync(root)
    _load_generation(root, portable['generationId'], selector['generationHash'])
    return {'mode': 'profile', 'generationId': portable['generationId'], 'keyCount': len(keys)}
