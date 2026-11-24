#!/usr/bin/env python3
"""Project-local payload custody. SHA-256 commits bytes, not their truth or availability."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
URI = re.compile(r"ava-evidence:sha256:([0-9a-f]{64})\Z")


def local(path):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.resolve().is_relative_to(ROOT):
        raise ValueError("path must stay in this project")
    for part in [path, *path.parents]:
        if part == ROOT:
            break
        if part.is_symlink():
            raise ValueError("symlinks are not allowed")
    return path


def receipt(data):
    digest = hashlib.sha256(data).hexdigest()
    return {"version": 1, "algorithm": "sha256", "commitment": "0x" + digest,
            "byteLength": len(data), "uri": "ava-evidence:sha256:" + digest}


def locations(store, uri):
    match = URI.fullmatch(uri)
    if not match:
        raise ValueError("invalid evidence URI")
    directory = local(local(store) / match[1])
    return local(directory / "payload"), local(directory / "receipt.json")


def inspect(store, uri):
    payload, record = locations(store, uri)
    try:
        data = payload.read_bytes()
        recorded = json.loads(record.read_text())
    except FileNotFoundError:
        return {"status": "unavailable", "uri": uri}, None
    except (ValueError, UnicodeError):
        return {"status": "integrity_mismatch", "uri": uri}, None
    expected = receipt(data)
    if expected["uri"] != uri or recorded != expected:
        return {"status": "integrity_mismatch", "uri": uri}, None
    return {"status": "available", **expected}, data


def put(store, source):
    data = local(source).read_bytes()
    result = receipt(data)
    payload, record = locations(store, result["uri"])
    store = local(store)
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(store, 0o700)
    payload.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(payload.parent, 0o700)
    # Never repair or overwrite a partially missing/corrupt receipt silently.
    if payload.exists() or record.exists():
        status, _ = inspect(store, result["uri"])
        if status["status"] != "available":
            raise ValueError("existing evidence is incomplete or corrupt; preserve it for investigation")
        return result
    with payload.open("xb") as output:
        os.chmod(payload, 0o600)
        output.write(data)
    with record.open("x") as output:
        os.chmod(record, 0o600)
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=".local/evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("put").add_argument("source")
    commands.add_parser("verify").add_argument("uri")
    read = commands.add_parser("read")
    read.add_argument("uri")
    read.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        if args.command == "put":
            result = put(args.store, args.source)
        else:
            result, data = inspect(args.store, args.uri)
            if args.command == "read" and data is not None:
                target = local(args.output)
                # Exclusive creation avoids overwriting source or earlier retrievals.
                with target.open("xb") as output:
                    os.chmod(target, 0o600)
                    output.write(data)
        print(json.dumps(result, sort_keys=True))
        return {"unavailable": 2, "integrity_mismatch": 3}.get(result.get("status"), 0)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "error", "message": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
