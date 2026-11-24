"""Bounded local custody backups of encrypted Vault records and exact receipts.

Keys are caller-owned bytes in memory; this module has no CLI or key store.
Backup reads require the source Vault's current authorizer. Restore checks record
integrity offline and returns receipts, never a Vault with an integrity-only
authorizer. Open restored files with the appropriate current authorizer; a backup
does not restore grants, registry state, active keys, or chain trust.
"""

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from privacy_vault import MAX_RECORD_BYTES, Vault, VaultError
from private_files import private_bytes

MAX_BACKUP_BYTES = 32 * 1024 * 1024
MAX_BACKUP_RECORDS = 128
_MAGIC = b"AVA-PRIVATE-BACKUP\x00\x01"
_MAGIC_V2 = b"AVA-PRIVATE-BACKUP\x00\x02"
_IDENTIFIER = re.compile(r"0x[0-9a-f]{64}\Z")
_RECEIPT_FIELDS = {"resourceId", "appId", "caseId", "policyId", "materialClass",
                   "ciphertextHash", "uri"}
_CHECK_ID = "0x" + "0" * 63 + "1"


class BackupError(VaultError):
    """An unsafe, unavailable, or unauthenticated backup was rejected."""


def _key(key):
    if type(key) is not bytes or len(key) != 32:
        raise BackupError("A caller-owned 32-byte key is required")
    return key


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise BackupError("Invalid backup metadata") from None


def _receipt(receipt):
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise BackupError("An exact Vault receipt is required")
    resource = receipt["resourceId"]
    if (type(resource) is not str or not _IDENTIFIER.fullmatch(resource)
            or int(resource, 16) == 0):
        raise BackupError("Invalid resource identifier")
    # Copy JSON-native values; comparison with Vault.receipt validates every field.
    return json.loads(_json(receipt))


@contextmanager
def _parent(path):
    """Pin every parent component without following a symbolic link."""
    fd = None
    try:
        path = Path(path)
        if ".." in path.parts:
            raise BackupError("Unsafe backup path")
        path = path.absolute()
        if path == Path(path.anchor):
            raise BackupError("Unsafe backup path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(path.anchor, flags)
        for component in path.parts[1:-1]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield path, fd
    except OSError:
        raise BackupError("Backup path unavailable or unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)


def _read_file(directory, name, limit):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > limit):
                raise BackupError("Unsafe backup material")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise BackupError("Backup material exceeds its size limit")
        return data
    except OSError:
        raise BackupError("Backup material unavailable or unsafe") from None


def _write_file(directory, name, data):
    created = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        created = True
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        if created:
            os.unlink(name, dir_fd=directory)
        raise BackupError("Cannot create private backup material") from None


def _empty_stage(directory):
    """Remove staged records and profile metadata without following links."""
    for name in os.listdir(directory):
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                _empty_stage(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory)
        else:
            os.unlink(name, dir_fd=directory)


def create_backup(vault, receipts, destination, backup_key, *, persona, role, purpose):
    """Create an exclusive encrypted bundle after currently authorized Vault reads.

    Supply 1..128 exact receipts, a fresh destination file, and an independent
    32-byte backup key held separately from the file. The bundle is at most 32 MiB.
    The bundle contains selected encrypted records and public receipts; rotated
    sources also include the sealed portable profile, never the active key.
    """
    _key(backup_key)
    if type(receipts) not in (list, tuple) or not 1 <= len(receipts) <= MAX_BACKUP_RECORDS:
        raise BackupError("Provide a bounded nonempty receipt list")
    entries, seen, size = [], set(), 0
    for value in receipts:
        receipt = _receipt(value)
        resource = receipt["resourceId"]
        if resource in seen:
            raise BackupError("Duplicate backup resource")
        seen.add(resource)
        if _json(vault.receipt(resource)) != _json(receipt):
            raise BackupError("Vault receipt mismatch")
        vault.read(resource, persona, role, purpose)
        with _parent(vault.root / (resource[2:] + ".json")) as (path, directory):
            record = _read_file(directory, path.name, MAX_RECORD_BYTES)
        if receipt["ciphertextHash"] != "0x" + hashlib.sha256(record).hexdigest():
            raise BackupError("Vault ciphertext changed during backup")
        encoded = base64.b64encode(record).decode("ascii")
        size += len(encoded) + len(_json(receipt)) + 64
        if size > MAX_BACKUP_BYTES - 128:
            raise BackupError("Backup exceeds its size limit")
        entries.append({"receipt": receipt, "record": encoded})
    from custody_credentials import portable_profile
    profile = portable_profile(vault)
    package = {"version": 1, "records": entries} if profile is None else {
        "version": 2, "records": entries, "profile": profile}
    magic = _MAGIC if profile is None else _MAGIC_V2
    plaintext = _json(package)
    nonce = os.urandom(12)
    encoded = magic + nonce + AESGCM(backup_key).encrypt(nonce, plaintext, magic)
    if len(encoded) > MAX_BACKUP_BYTES:
        raise BackupError("Backup exceeds its size limit")
    with _parent(destination) as (path, directory):
        _write_file(directory, path.name, encoded)
        try:
            os.fsync(directory)
        except OSError:
            os.unlink(path.name, dir_fd=directory)
            raise BackupError("Backup write failed") from None


def _unpack(encoded, backup_key):
    magic = _MAGIC if encoded.startswith(_MAGIC) else _MAGIC_V2 if encoded.startswith(_MAGIC_V2) else None
    if magic is None or len(encoded) < len(magic) + 28:
        raise BackupError("Invalid encrypted backup")
    offset = len(magic)
    try:
        plaintext = AESGCM(backup_key).decrypt(encoded[offset:offset + 12], encoded[offset + 12:], magic)
    except (InvalidTag, ValueError):
        raise BackupError("Backup authentication failed") from None
    try:
        package = json.loads(plaintext)
    except (ValueError, UnicodeError, RecursionError):
        raise BackupError("Invalid backup package") from None
    expected_version = 1 if magic == _MAGIC else 2
    expected_fields = {"version", "records"} if expected_version == 1 else {"version", "records", "profile"}
    if (type(package) is not dict or set(package) != expected_fields
            or type(package["version"]) is not int or package["version"] != expected_version
            or type(package["records"]) is not list
            or not 1 <= len(package["records"]) <= MAX_BACKUP_RECORDS
            or (expected_version == 2 and type(package["profile"]) is not dict)
            or _json(package) != plaintext):
        raise BackupError("Invalid backup package")
    entries, seen = [], set()
    for entry in package["records"]:
        if type(entry) is not dict or set(entry) != {"receipt", "record"}:
            raise BackupError("Invalid backup entry")
        receipt = _receipt(entry["receipt"])
        resource = receipt["resourceId"]
        if resource in seen:
            raise BackupError("Duplicate backup resource")
        seen.add(resource)
        try:
            record = base64.b64decode(entry["record"], validate=True)
            if base64.b64encode(record).decode("ascii") != entry["record"]:
                raise ValueError()
        except (ValueError, TypeError):
            raise BackupError("Invalid encrypted backup record") from None
        if len(record) > MAX_RECORD_BYTES:
            raise BackupError("Encrypted record exceeds its size limit")
        entries.append((receipt, record))
    return entries, package.get("profile") if expected_version == 2 else None


def restore_backup(backup_path, destination, backup_key, master_key, *, active_key_file=None,
                   credential_profile_file=None):
    """Authenticate and atomically publish ciphertext into a fresh private folder.

    master_key authenticates the existing Vault format; it is never saved. A
    rotated backup requires its matching private active_key_file. A current
    credential profile can instead supply retained keys for an older backup. The
    returned exact receipts are references for current registry checks, not read
    authority. Destination parents must exist and contain no symbolic links.
    """
    _key(backup_key)
    _key(master_key)
    with _parent(backup_path) as (path, directory):
        encoded = _read_file(directory, path.name, MAX_BACKUP_BYTES)
    entries, archived_profile = _unpack(encoded, backup_key)
    profile = archived_profile
    current_vault = None
    if profile is not None or credential_profile_file is not None:
        try:
            if active_key_file is None or not hmac.compare_digest(private_bytes(active_key_file, 32), master_key):
                raise ValueError()
        except (OSError, TypeError, ValueError):
            raise BackupError("Active credential file does not match the supplied master key") from None
    elif active_key_file is not None:
        raise BackupError("Legacy backup requires its original master key")
    if credential_profile_file is not None:
        try:
            from custody_credentials import open_vault, portable_profile
            selected = Path(credential_profile_file)
            current_vault = open_vault(selected.parent, lambda *_: False,
                                       credential_profile_file=selected)
            profile = portable_profile(current_vault)
            if profile is None:
                raise VaultError("Current credential profile required")
            if archived_profile is not None:
                from custody_credentials import authenticate_portable_profile
                authenticate_portable_profile(archived_profile, current_vault)
        except (OSError, TypeError, ValueError):
            raise BackupError("Current credential profile could not authenticate the backup") from None
    with _parent(destination) as (path, parent):
        stage_name = ".ava-restore-" + os.urandom(12).hex()
        directory, committed, published = None, False, False
        stage_identity = reservation_identity = None
        try:
            os.mkdir(stage_name, 0o700, dir_fd=parent)
            stage_identity = os.stat(stage_name, dir_fd=parent, follow_symlinks=False).st_ino
            directory = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.fchmod(directory, 0o700)
            stage_path = path.parent / stage_name
            if profile is not None:
                from custody_credentials import install_portable_profile
                install_portable_profile(stage_path, profile, active_key_file)
            for receipt, record in entries:
                name = receipt["resourceId"][2:] + ".json"
                _write_file(directory, name, record)
                # Integrity validation is local custody, not an access grant. No
                # permissive Vault escapes this function or reaches live service.
                authorizer = lambda actual, *_: _json(actual) == _json(receipt)
                if profile is None:
                    verifier = Vault(stage_path, master_key, authorizer)
                else:
                    from custody_credentials import open_vault
                    verifier = open_vault(stage_path, authorizer,
                                          credential_profile_file=stage_path / ".ava-custody-profile.json")
                if _json(verifier.receipt(receipt["resourceId"])) != _json(receipt):
                    raise BackupError("Restored receipt mismatch")
                verifier.read(receipt["resourceId"], _CHECK_ID, _CHECK_ID, _CHECK_ID)
            os.fsync(directory)
            if current_vault is not None and portable_profile(current_vault) != profile:
                raise BackupError("Current credential profile changed during restore")
            # Reserve exclusively before atomic rename: os.rename alone could
            # overwrite a pre-existing empty directory on POSIX.
            os.mkdir(path.name, 0o700, dir_fd=parent)
            reservation_identity = os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_ino
            os.rename(stage_name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            published = True
            os.fsync(parent)
            committed = True
        except (OSError, VaultError):
            raise BackupError("Restore rejected; no destination was accepted") from None
        finally:
            if directory is not None:
                if not committed:
                    _empty_stage(directory)
                os.close(directory)
            if not committed:
                candidates = [(stage_name, stage_identity),
                              (path.name, stage_identity if published else reservation_identity)]
                for name, identity in candidates:
                    if identity is None:
                        continue
                    try:
                        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode) and info.st_ino == identity:
                            os.rmdir(name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
        return [receipt for receipt, _ in entries]
