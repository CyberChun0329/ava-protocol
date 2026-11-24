#!/usr/bin/env python3
"""Fixed app-neutral JSON-stdio bridge to the existing encrypted material Vault."""

import base64
import json
from pathlib import Path
import sys

MAX_WIRE_BYTES = 4 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024
DRAFT_POLICY_ID = 1
PERSONA = "0x" + "1".rjust(64, "0")
ROLE = "0x" + "2".rjust(64, "0")
PURPOSE = "0x" + "3".rjust(64, "0")
RECEIPT_FIELDS = {"resourceId", "appId", "caseId", "policyId", "materialClass", "ciphertextHash", "uri"}

sys.path.insert(0, str(Path(__file__).resolve().parent))


class RequestError(ValueError):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RequestError()
        value[key] = item
    return value


def identifier(value):
    if (not isinstance(value, str) or len(value) != 66 or not value.startswith("0x")
            or any(ch not in "0123456789abcdef" for ch in value[2:]) or int(value[2:], 16) == 0):
        raise RequestError()
    return value


def metadata_json(value):
    if not isinstance(value, dict):
        raise RequestError()
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise RequestError() from None
    return encoded


def parse_request():
    raw = sys.stdin.buffer.read(MAX_WIRE_BYTES + 1)
    if len(raw) > MAX_WIRE_BYTES:
        raise RequestError()
    try:
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(RequestError()))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise RequestError() from None
    if not isinstance(value, dict):
        raise RequestError()
    return value


def credential_fields(value):
    choices = {field for field in ("masterKeyFile", "credentialProfileFile") if field in value}
    if len(choices) != 1:
        raise RequestError()
    return choices


def load_vault(value):
    from private_files import project_path
    from custody_credentials import open_vault
    fields = credential_fields(value)
    options = ({"master_key_file": project_path(value["masterKeyFile"])} if "masterKeyFile" in fields
               else {"credential_profile_file": project_path(value["credentialProfileFile"])})
    return open_vault(project_path(value["vaultPath"]), lambda *_: False, **options)


def check(value):
    from custody_credentials import inspect_credentials
    expected = {"operation", "vaultPath"} | credential_fields(value)
    if set(value) != expected:
        raise RequestError()
    vault = load_vault(value)
    status = inspect_credentials(vault.root)
    if status["mode"] not in ("legacy", "profile"):
        raise RequestError()
    return status


def put(value):
    expected = {"operation", "vaultPath", "appId", "caseId",
                "materialClass", "payloadBase64", "metadata"} | credential_fields(value)
    if set(value) != expected or value["operation"] != "put":
        raise RequestError()
    app_id = identifier(value["appId"])
    case_id = identifier(value["caseId"])
    material_class = identifier(value["materialClass"])
    payload_text = value["payloadBase64"]
    if not isinstance(payload_text, str):
        raise RequestError()
    try:
        payload = base64.b64decode(payload_text, validate=True)
    except (ValueError, TypeError):
        raise RequestError() from None
    if base64.b64encode(payload).decode("ascii") != payload_text:
        raise RequestError()
    metadata = value["metadata"]
    if len(payload) > MAX_PLAINTEXT_BYTES or len(payload) + len(metadata_json(metadata)) + 4 > MAX_PLAINTEXT_BYTES:
        raise RequestError()
    vault = load_vault(value)
    receipt = vault.put(app_id, case_id, DRAFT_POLICY_ID, material_class, payload, metadata)
    if receipt["policyId"] != DRAFT_POLICY_ID:
        raise RequestError()
    return receipt


def read(value):
    expected = {"operation", "vaultPath", "receipt"} | credential_fields(value)
    if set(value) != expected or value["operation"] != "read":
        raise RequestError()
    request_receipt = value["receipt"]
    if not isinstance(request_receipt, dict) or set(request_receipt) != RECEIPT_FIELDS:
        raise RequestError()
    checked = dict(request_receipt)
    checked["resourceId"] = identifier(checked["resourceId"])
    for field in ("appId", "caseId", "materialClass"):
        identifier(checked[field])
    if (type(checked["policyId"]) is not int or checked["policyId"] != DRAFT_POLICY_ID
            or not isinstance(checked["ciphertextHash"], str)
            or len(checked["ciphertextHash"]) != 66 or not checked["ciphertextHash"].startswith("0x")
            or any(ch not in "0123456789abcdef" for ch in checked["ciphertextHash"][2:])
            or checked["uri"] != "ava-private:v1:" + checked["resourceId"][2:]):
        raise RequestError()
    vault = load_vault(value)
    def exact_draft(actual, persona, role, purpose):
        return (actual == checked and actual["appId"] == checked["appId"]
                and actual["policyId"] == DRAFT_POLICY_ID
                and (persona, role, purpose) == (PERSONA, ROLE, PURPOSE))

    payload, metadata = vault.read(checked["resourceId"], PERSONA, ROLE, PURPOSE,
                                  authorizer=exact_draft)
    if len(payload) + len(metadata_json(metadata)) + 4 > MAX_PLAINTEXT_BYTES:
        raise RequestError()
    return {"payloadBase64": base64.b64encode(payload).decode("ascii"), "metadata": metadata}


def main():
    try:
        value = parse_request()
        if value.get("operation") == "check":
            result = check(value)
        elif value.get("operation") == "put":
            result = put(value)
        elif value.get("operation") == "read":
            result = read(value)
        else:
            raise RequestError()
        output = json.dumps(result, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(output) > MAX_WIRE_BYTES:
            raise RequestError()
        sys.stdout.buffer.write(output)
    except Exception:
        sys.stderr.write("E_CUSTODY\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
