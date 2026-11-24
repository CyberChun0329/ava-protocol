#!/usr/bin/env python3
"""Trusted stopped-operator stdio adapter; never mounted as an HTTP endpoint."""
import json
import sys

from material_custody import parse_request, credential_fields, RequestError
from private_files import project_path
from custody_credentials import (open_vault, prepare_rotation, activate_rotation,
                                 inspect_credentials, portable_profile, install_portable_profile)


def credentials(value):
    fields = credential_fields(value)
    return ({'master_key_file': project_path(value['masterKeyFile'])} if 'masterKeyFile' in fields
            else {'credential_profile_file': project_path(value['credentialProfileFile'])})


def operate(value):
    operation = value.get('operation')
    root = project_path(value['vaultPath'])
    base = {'operation', 'vaultPath'}
    if operation == 'prepare':
        if set(value) != base | {'newMasterKeyFile', 'expectedReceipts'} | credential_fields(value):
            raise RequestError()
        return prepare_rotation(root, new_master_key_file=project_path(value['newMasterKeyFile']),
                                expected_receipts=value['expectedReceipts'], **credentials(value))
    if operation == 'activate' and set(value) == base | {'generationId'}:
        return activate_rotation(root, value['generationId'])
    if operation == 'inspect' and set(value) == base:
        return inspect_credentials(root)
    if operation == 'export-profile' and set(value) == base | credential_fields(value):
        vault = open_vault(root, lambda *_: False, **credentials(value))
        profile = portable_profile(vault)
        if profile is None:
            raise RequestError()
        return {'mode': 'portable', 'profile': profile}
    if operation == 'install-profile' and set(value) == base | {'profile', 'activeKeyFile'}:
        return install_portable_profile(root, value['profile'], project_path(value['activeKeyFile']))
    raise RequestError()


def main():
    try:
        output = json.dumps(operate(parse_request()), sort_keys=True, separators=(',', ':'),
                            ensure_ascii=False, allow_nan=False).encode('utf8')
        if len(output) > 4 * 1024 * 1024:
            raise RequestError()
        sys.stdout.buffer.write(output)
        return 0
    except Exception:
        sys.stderr.write('E_CUSTODY\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
