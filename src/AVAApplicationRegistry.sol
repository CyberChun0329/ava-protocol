// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVACoreTypes} from "./core/AVACoreTypes.sol";

/// @notice Append-only registry of AVA application namespaces.
/// @dev Namespace metadata is immutable; root and application management are separate from business roles.
contract AVAApplicationRegistry {
    struct ApplicationRecord {
        bytes32 appId;
        bytes32 applicationIdentityHash;
        bytes32 authorityId;
        string uri;
        address registeredBy;
    }

    address public ADMIN;
    address public pendingAdmin;
    uint256 public adminVersion = 1;

    mapping(bytes32 => ApplicationRecord) private applications;
    mapping(bytes32 => address) public applicationAdmin;
    mapping(bytes32 => address) public pendingApplicationAdmin;
    mapping(bytes32 => uint256) public pendingApplicationAdminVersion;

    event ApplicationRegistered(
        bytes32 indexed appId,
        bytes32 indexed applicationIdentityHash,
        bytes32 indexed authorityId,
        string uri,
        address registeredBy
    );
    event AdminTransferProposed(address indexed currentAdmin, address indexed proposedAdmin);
    event AdminTransferCancelled(address indexed currentAdmin, address indexed cancelledAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event ApplicationAdminTransferProposed(
        bytes32 indexed appId, address indexed currentAdmin, address indexed proposedAdmin, address proposedBy
    );
    event ApplicationAdminTransferCancelled(bytes32 indexed appId, address indexed cancelledAdmin, address actor);
    event ApplicationAdminChanged(
        bytes32 indexed appId, address indexed previousAdmin, address indexed newAdmin, address actor
    );

    constructor(address initialAdmin) {
        if (initialAdmin == address(0) || initialAdmin == address(this)) revert AVACoreTypes.EmptyValue();
        ADMIN = initialAdmin;
        emit AdminTransferred(address(0), initialAdmin);
    }

    modifier onlyAdmin() {
        if (msg.sender != ADMIN) revert AVACoreTypes.NotAdmin(msg.sender);
        _;
    }

    function proposeAdmin(address proposedAdmin) external onlyAdmin {
        if (proposedAdmin == address(0) || proposedAdmin == address(this) || proposedAdmin == ADMIN) {
            revert AVACoreTypes.EmptyValue();
        }
        pendingAdmin = proposedAdmin;
        emit AdminTransferProposed(ADMIN, proposedAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin || pendingAdmin == address(0)) revert AVACoreTypes.NotAdmin(msg.sender);
        address previousAdmin = ADMIN;
        ADMIN = msg.sender;
        delete pendingAdmin;
        // Pending app handovers must be proposed again under the new root administration.
        ++adminVersion;
        emit AdminTransferred(previousAdmin, msg.sender);
    }

    function cancelAdminTransfer() external onlyAdmin {
        address cancelled = pendingAdmin;
        delete pendingAdmin;
        emit AdminTransferCancelled(ADMIN, cancelled);
    }

    function proposeApplicationAdmin(bytes32 appId, address proposedAdmin) external {
        _requireApplicationAdmin(msg.sender, appId);
        if (proposedAdmin == address(0) || proposedAdmin == address(this) || proposedAdmin == applicationAdmin[appId]) {
            revert AVACoreTypes.EmptyValue();
        }
        pendingApplicationAdmin[appId] = proposedAdmin;
        pendingApplicationAdminVersion[appId] = adminVersion;
        emit ApplicationAdminTransferProposed(appId, applicationAdmin[appId], proposedAdmin, msg.sender);
    }

    function acceptApplicationAdmin(bytes32 appId) external {
        _requireApplication(appId);
        if (
            msg.sender != pendingApplicationAdmin[appId] || pendingApplicationAdmin[appId] == address(0)
                || pendingApplicationAdminVersion[appId] != adminVersion
        ) revert AVACoreTypes.NotAdmin(msg.sender);
        address previousAdmin = applicationAdmin[appId];
        applicationAdmin[appId] = msg.sender;
        _clearPendingApplicationAdmin(appId);
        emit ApplicationAdminChanged(appId, previousAdmin, msg.sender, msg.sender);
    }

    function cancelApplicationAdminTransfer(bytes32 appId) external {
        _requireApplicationAdmin(msg.sender, appId);
        address cancelled = pendingApplicationAdmin[appId];
        _clearPendingApplicationAdmin(appId);
        emit ApplicationAdminTransferCancelled(appId, cancelled, msg.sender);
    }

    /// @notice Revokes delegated management only; business-role revocation is explicit in the identity/matrix registries.
    function revokeApplicationAdmin(bytes32 appId) external onlyAdmin {
        _requireApplication(appId);
        address previousAdmin = applicationAdmin[appId];
        address cancelled = pendingApplicationAdmin[appId];
        delete applicationAdmin[appId];
        _clearPendingApplicationAdmin(appId);
        emit ApplicationAdminTransferCancelled(appId, cancelled, msg.sender);
        emit ApplicationAdminChanged(appId, previousAdmin, address(0), msg.sender);
    }

    function requireApplicationAdmin(address account, bytes32 appId) external view {
        _requireApplicationAdmin(account, appId);
    }

    function _requireApplicationAdmin(address account, bytes32 appId) private view {
        _requireApplication(appId);
        if (account == address(0) || (account != ADMIN && account != applicationAdmin[appId])) {
            revert AVACoreTypes.NotAdmin(account);
        }
    }

    function _clearPendingApplicationAdmin(bytes32 appId) private {
        delete pendingApplicationAdmin[appId];
        delete pendingApplicationAdminVersion[appId];
    }

    function _requireApplication(bytes32 appId) private view {
        if (applications[appId].appId == bytes32(0)) revert AVACoreTypes.UnknownReference(uint256(appId));
    }

    function registerApplication(
        bytes32 appId,
        bytes32 applicationIdentityHash,
        bytes32 authorityId,
        address initialApplicationAdmin,
        string calldata uri
    ) external onlyAdmin {
        if (
            appId == bytes32(0) || applicationIdentityHash == bytes32(0) || authorityId == bytes32(0)
                || initialApplicationAdmin == address(0) || initialApplicationAdmin == address(this)
                || bytes(uri).length == 0
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        if (applications[appId].appId != bytes32(0)) {
            revert AVACoreTypes.InvalidState(uint256(appId));
        }

        applications[appId] = ApplicationRecord({
            appId: appId,
            applicationIdentityHash: applicationIdentityHash,
            authorityId: authorityId,
            uri: uri,
            registeredBy: msg.sender
        });
        applicationAdmin[appId] = initialApplicationAdmin;
        emit ApplicationRegistered(appId, applicationIdentityHash, authorityId, uri, msg.sender);
        emit ApplicationAdminChanged(appId, address(0), initialApplicationAdmin, msg.sender);
    }

    function getApplication(bytes32 appId) public view returns (ApplicationRecord memory record) {
        record = applications[appId];
        if (record.appId == bytes32(0)) revert AVACoreTypes.UnknownReference(uint256(appId));
    }

    /// @notice Validates an application reference without returning dynamic metadata.
    function requireApplicationReference(bytes32 appId) external view {
        _requireApplication(appId);
    }
}
