// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVAApplicationRegistry} from "../AVAApplicationRegistry.sol";
import {AVACoreTypes} from "./AVACoreTypes.sol";
import {AVAIdentityRegistry} from "./AVAIdentityRegistry.sol";

contract AVAAuthorityMatrix {
    struct PermissionUpdate {
        bytes32 roleKey;
        bytes32 actionKey;
        bool allowed;
    }

    AVAApplicationRegistry public immutable APPLICATION_REGISTRY;
    AVAIdentityRegistry public immutable IDENTITY_REGISTRY;

    mapping(bytes32 => bool) private permissions;

    event PermissionConfigured(bytes32 indexed appId, bytes32 indexed roleKey, bytes32 indexed actionKey, bool allowed);

    constructor(AVAApplicationRegistry applicationRegistry_, AVAIdentityRegistry identityRegistry_) {
        if (address(applicationRegistry_) == address(0) || address(identityRegistry_) == address(0)) {
            revert AVACoreTypes.EmptyValue();
        }
        if (address(identityRegistry_.APPLICATION_REGISTRY()) != address(applicationRegistry_)) {
            revert AVACoreTypes.InvalidState(0);
        }
        APPLICATION_REGISTRY = applicationRegistry_;
        IDENTITY_REGISTRY = identityRegistry_;
    }

    function setPermission(bytes32 appId, bytes32 roleKey, bytes32 actionKey, bool allowed) external {
        if (appId == bytes32(0) || roleKey == bytes32(0) || actionKey == bytes32(0)) {
            revert AVACoreTypes.EmptyValue();
        }
        APPLICATION_REGISTRY.requireApplicationAdmin(msg.sender, appId);
        _setPermission(appId, roleKey, actionKey, allowed);
    }

    function setPermissions(bytes32 appId, PermissionUpdate[] calldata updates) external {
        if (appId == bytes32(0) || updates.length == 0) revert AVACoreTypes.EmptyValue();
        APPLICATION_REGISTRY.requireApplicationAdmin(msg.sender, appId);
        for (uint256 i; i < updates.length; ++i) {
            PermissionUpdate calldata update = updates[i];
            if (update.roleKey == bytes32(0) || update.actionKey == bytes32(0)) revert AVACoreTypes.EmptyValue();
            _setPermission(appId, update.roleKey, update.actionKey, update.allowed);
        }
    }

    function _setPermission(bytes32 appId, bytes32 roleKey, bytes32 actionKey, bool allowed) private {
        permissions[_permissionKey(appId, roleKey, actionKey)] = allowed;
        emit PermissionConfigured(appId, roleKey, actionKey, allowed);
    }

    function isAuthorised(address account, bytes32 appId, bytes32 roleKey, bytes32 actionKey)
        public
        view
        returns (bool)
    {
        return permissions[_permissionKey(appId, roleKey, actionKey)]
            && IDENTITY_REGISTRY.subjectOf(account, appId, roleKey) != bytes32(0);
    }

    function isAuthorisedSubject(
        address account,
        bytes32 appId,
        bytes32 roleKey,
        bytes32 actionKey,
        bytes32 authorityId
    ) external view returns (bool) {
        return authorityId != bytes32(0) && IDENTITY_REGISTRY.subjectOf(account, appId, roleKey) == authorityId
            && permissions[_permissionKey(appId, roleKey, actionKey)];
    }

    function requireAuthorisedCanonicalSubject(address account, bytes32 appId, bytes32 roleKey, bytes32 actionKey)
        public
        view
        returns (bytes32 subjectId)
    {
        if (!permissions[_permissionKey(appId, roleKey, actionKey)]) {
            revert AVACoreTypes.NotAuthorised(account, actionKey);
        }
        subjectId = IDENTITY_REGISTRY.subjectOf(account, appId, roleKey);
        if (subjectId == bytes32(0)) revert AVACoreTypes.NotAuthorised(account, actionKey);
    }

    function requireAuthorisedSubject(
        address account,
        bytes32 appId,
        bytes32 roleKey,
        bytes32 actionKey,
        bytes32 authorityId
    ) external view returns (bytes32 subjectId) {
        subjectId = requireAuthorisedCanonicalSubject(account, appId, roleKey, actionKey);
        if (subjectId != authorityId) revert AVACoreTypes.SubjectMismatch(subjectId, authorityId);
    }

    function _permissionKey(bytes32 appId, bytes32 roleKey, bytes32 actionKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(appId, roleKey, actionKey));
    }
}
