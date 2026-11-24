"""Local encrypted storage; callers authenticate uploads and authorize every read.

The master key is caller-managed and is never written here. The authorizer must
verify the entire receipt against the registry before returning True. This vault
does not authenticate a persona, hide public context or ciphertext size, or
protect secrets from the local custodian running this process.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    raise ImportError(
        "Privacy vault requires cryptography; install requirements-privacy.txt "
        "in the project privacy virtual environment."
    ) from exc


MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024
MAX_RECORD_BYTES = ((MAX_PLAINTEXT_BYTES + 18) // 3) * 4 + 4096
_HEX32 = re.compile(r"0x[0-9a-f]{64}\Z")
_CONTEXT_FIELDS = {"resourceId", "appId", "caseId", "policyId", "materialClass"}
_RECORD_FIELDS = {"version", "context", "wrapNonce", "wrappedKey", "dataNonce", "ciphertext"}


class VaultError(ValueError):
    """Missing, invalid, unsafe, or unauthenticated vault material."""


class AccessDenied(PermissionError):
    """The current authorization check did not explicitly allow the read."""


def _hex32(value):
    if not isinstance(value, str) or not _HEX32.fullmatch(value) or int(value, 16) == 0:
        raise VaultError("Expected a nonzero canonical bytes32 identifier")
    return value


def _context(resource_id, app_id, case_id, policy_id, material_class):
    if type(policy_id) is not int or not 0 < policy_id < 2**256:
        raise VaultError("Invalid policy identifier")
    return {
        "resourceId": _hex32(resource_id), "appId": _hex32(app_id),
        "caseId": _hex32(case_id), "policyId": policy_id,
        "materialClass": _hex32(material_class),
    }


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise VaultError("Invalid JSON value") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VaultError("Duplicate JSON field")
        result[key] = value
    return result


def _parse(data):
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(VaultError("Invalid JSON constant")))
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise VaultError("Invalid encrypted record") from exc


def _metadata(value):
    # Restrict to JSON-native types so encoding never silently changes key types.
    def check(item):
        if isinstance(item, dict):
            return all(type(k) is str and check(v) for k, v in item.items())
        if isinstance(item, list):
            return all(check(v) for v in item)
        return item is None or type(item) in (str, int, float, bool)
    try:
        if not isinstance(value, dict) or not check(value):
            raise VaultError("Metadata must be a JSON object")
        return _json(value)
    except RecursionError as exc:
        raise VaultError("Invalid metadata") from exc


def _encode(value):
    return base64.b64encode(value).decode("ascii")


def _decode(value, expected=None):
    try:
        if not isinstance(value, str):
            raise ValueError()
        result = base64.b64decode(value, validate=True)
        if _encode(result) != value or (expected is not None and len(result) != expected):
            raise ValueError()
        return result
    except (ValueError, TypeError) as exc:
        raise VaultError("Invalid encrypted record") from exc


def _aad(context, domain):
    return b"ava-private:v1:" + domain + b"\0" + _json(context)


class Vault:
    def __init__(self, root: Path, master_key: bytes, authorizer: Callable, *, _credential_state=None):
        if type(master_key) is not bytes or len(master_key) != 32:
            raise VaultError("Master key must contain exactly 32 bytes")
        if not callable(authorizer):
            raise VaultError("An authorizer is required")
        root = Path(root)
        if ".." in root.parts:
            raise VaultError("Unsafe vault root")
        self.root = root.absolute()
        if self.root == Path(self.root.anchor):
            raise VaultError("Unsafe vault root")
        self._master_key = master_key
        self._authorizer = authorizer
        self._credential_state = _credential_state
        with self._directory(create=True):
            pass
        self._check_credentials()

    def _check_credentials(self):
        if self._credential_state is not None:
            self._credential_state.validate()
            return
        with self._directory() as directory:
            for name in ('.ava-custody-profile.json', '.ava-custody-managed'):
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise VaultError('Managed vault requires its selected credential profile')

    @contextmanager
    def _directory(self, create=False):
        """Open each component relative to a pinned directory, without symlinks."""
        fd = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open(self.root.anchor, flags)
            parts = self.root.parts[1:]
            for index, part in enumerate(parts):
                if create and index == len(parts) - 1:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise VaultError("Unsafe vault directory permissions")
            yield fd
        except OSError as exc:
            raise VaultError("Vault storage unavailable or unsafe") from exc
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _filename(resource_id):
        return _hex32(resource_id)[2:] + ".json"

    def _load(self, resource_id):
        filename = self._filename(resource_id)
        try:
            with self._directory() as directory:
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                            or info.st_size > MAX_RECORD_BYTES):
                        raise VaultError("Unsafe encrypted record")
                    encoded = stream.read(MAX_RECORD_BYTES + 1)
        except OSError as exc:
            raise VaultError("Encrypted record unavailable or unsafe") from exc
        if len(encoded) > MAX_RECORD_BYTES:
            raise VaultError("Encrypted record too large")
        record = _parse(encoded)
        if (not isinstance(record, dict) or set(record) != _RECORD_FIELDS
                or type(record["version"]) is not int or record["version"] != 1
                or not isinstance(record["context"], dict)
                or set(record["context"]) != _CONTEXT_FIELDS):
            raise VaultError("Invalid encrypted record")
        context = record["context"]
        checked = _context(context["resourceId"], context["appId"], context["caseId"],
                           context["policyId"], context["materialClass"])
        if checked["resourceId"] != resource_id or _json(record) != encoded:
            raise VaultError("Encrypted record identity mismatch")
        _decode(record["wrapNonce"], 12)
        _decode(record["dataNonce"], 12)
        _decode(record["wrappedKey"], 48)
        ciphertext = _decode(record["ciphertext"])
        if not 20 <= len(ciphertext) <= MAX_PLAINTEXT_BYTES + 16:
            raise VaultError("Invalid encrypted payload size")
        return record, encoded

    @staticmethod
    def _receipt(record, encoded):
        return dict(record["context"], ciphertextHash="0x" + hashlib.sha256(encoded).hexdigest(),
                    uri="ava-private:v1:" + record["context"]["resourceId"][2:])

    def put(self, app_id: str, case_id: str, policy_id: int, material_class: str,
            payload: bytes, metadata: dict, resource_id: str = None):
        """Store a new record exclusively. Upload authentication is caller-owned."""
        self._check_credentials()
        context = _context(resource_id if resource_id is not None else "0x" + os.urandom(32).hex(),
                           app_id, case_id, policy_id, material_class)
        if type(payload) is not bytes:
            raise VaultError("Payload must be bytes")
        if len(payload) > MAX_PLAINTEXT_BYTES:
            raise VaultError("Plaintext exceeds the 2 MiB limit")
        meta = _metadata(metadata)
        if len(payload) + len(meta) + 4 > MAX_PLAINTEXT_BYTES:
            raise VaultError("Plaintext exceeds the 2 MiB limit")
        plaintext = len(meta).to_bytes(4, "big") + meta + payload
        dek, wrap_nonce, data_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
        record = {
            "version": 1, "context": context, "wrapNonce": _encode(wrap_nonce),
            "wrappedKey": _encode(AESGCM(self._master_key).encrypt(wrap_nonce, dek, _aad(context, b"key"))),
            "dataNonce": _encode(data_nonce),
            "ciphertext": _encode(AESGCM(dek).encrypt(data_nonce, plaintext, _aad(context, b"content"))),
        }
        encoded = _json(record)
        filename = self._filename(context["resourceId"])
        with self._directory() as directory:
            try:
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
            except OSError as exc:
                raise VaultError("Cannot create a new encrypted record") from exc
            try:
                with os.fdopen(fd, "wb") as stream:
                    # Enforce exact permissions even under a more restrictive umask.
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            except OSError as exc:
                os.unlink(filename, dir_fd=directory)
                raise VaultError("Encrypted record write failed") from exc
        return self._receipt(record, encoded)

    def receipt(self, resource_id):
        """Commit to stored ciphertext and context without decrypting anything."""
        self._check_credentials()
        record, encoded = self._load(resource_id)
        return self._receipt(record, encoded)

    def read(self, resource_id, persona: str, role: str, purpose: str, *, authorizer=None):
        _, _, payload, metadata = self._open(resource_id, persona, role, purpose, authorizer)
        return payload, metadata

    def export_for_transfer(self, resource_id, persona: str, role: str, purpose: str, *, authorizer=None, validator=None):
        encoded, dek, payload, metadata = self._open(resource_id, persona, role, purpose, authorizer)
        if validator is not None and validator(payload, metadata) is not True:
            raise AccessDenied("Transfer material is not supported")
        return {"envelopeBase64": _encode(encoded), "contentKeyBase64": _encode(dek)}

    def _open(self, resource_id, persona, role, purpose, authorizer):
        persona, role, purpose = _hex32(persona), _hex32(role), _hex32(purpose)
        record, encoded = self._load(resource_id)
        try:
            allowed = (self._authorizer if authorizer is None else authorizer)(
                self._receipt(record, encoded), persona, role, purpose)
        except Exception:
            raise AccessDenied("Read authorization failed") from None
        if allowed is not True:
            raise AccessDenied("Read access denied")
        self._check_credentials()
        keys = self._credential_state.keys if self._credential_state is not None else (self._master_key,)
        dek, payload, metadata = self._decrypt_record(record, keys)
        return encoded, dek, payload, metadata

    @staticmethod
    def _decrypt_record(record, keys):
        context = record["context"]
        for key in keys:
            try:
                dek = AESGCM(key).decrypt(_decode(record["wrapNonce"], 12),
                    _decode(record["wrappedKey"], 48), _aad(context, b"key"))
                break
            except (InvalidTag, ValueError):
                continue
        else:
            raise VaultError("Encrypted record authentication failed") from None
        try:
            plaintext = AESGCM(dek).decrypt(
                _decode(record["dataNonce"], 12), _decode(record["ciphertext"]), _aad(context, b"content"))
        except (InvalidTag, ValueError):
            raise VaultError("Encrypted record authentication failed") from None
        if not 4 <= len(plaintext) <= MAX_PLAINTEXT_BYTES:
            raise VaultError("Invalid encrypted payload")
        length = int.from_bytes(plaintext[:4], "big")
        if length > len(plaintext) - 4:
            raise VaultError("Invalid encrypted metadata")
        metadata = _parse(plaintext[4:4 + length])
        if _metadata(metadata) != plaintext[4:4 + length]:
            raise VaultError("Invalid encrypted metadata")
        return dek, plaintext[4 + length:], metadata
