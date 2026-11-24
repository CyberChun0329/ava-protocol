// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAPrivacyRegistry} from "../src/extensions/privacy/AVAPrivacyRegistry.sol";
import {AVAGovernedDisclosure} from "../src/extensions/privacy/AVAGovernedDisclosure.sol";
import {AVAEvidenceResourceBinding} from "../src/extensions/privacy/AVAEvidenceResourceBinding.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface PrivacyBatchVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }
    function snapshotState() external returns (uint256);
    function revertToState(uint256 id) external returns (bool);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function expectRevert(bytes calldata reason) external;
}

contract PrivacyGrantBatchTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("privacy.batch.app");
    bytes32 private constant OBJECT = keccak256("privacy.batch.object");
    bytes32 private constant CASE_ID = keccak256("privacy.batch.case");
    bytes32 private constant MATERIAL = keccak256("privacy.batch.material");
    bytes32 private constant READER = keccak256("privacy.batch.reader");
    bytes32 private constant PURPOSE = keccak256("privacy.batch.purpose");
    bytes32 private constant FUTURE = keccak256("privacy.batch.future");
    bytes32 private constant PROTECTED = keccak256("privacy.batch.protected");
    AVAPrivacyRegistry private privacy;
    uint256 private policyId;
    PrivacyBatchVm private constant batchVm = PrivacyBatchVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string key, uint256 value);

    function setUp() public {
        requestVm.warp(1000);
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), OBJECT);
        privacy = new AVAPrivacyRegistry(authorityMatrix);
        AVAEvidenceResourceBinding bindings = new AVAEvidenceResourceBinding(privacy, evidenceRegistry);
        AVAGovernedDisclosure executor = new AVAGovernedDisclosure(
            privacy,
            requestAllocation,
            bindings,
            APP,
            REQUEST_WORKFLOW,
            OBJECT,
            keccak256("privacy.batch.disclose"),
            keccak256("privacy.batch.burden")
        );
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_POLICY(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_CASE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.REGISTER_RESOURCE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.GRANT_ACCESS(), true);
        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](3);
        rules[0] = AVAPrivacyRegistry.Rule(MATERIAL, READER, PURPOSE, 1, 1000, address(0));
        rules[1] = AVAPrivacyRegistry.Rule(MATERIAL, READER, FUTURE, 2, 1000, address(0));
        rules[2] = AVAPrivacyRegistry.Rule(MATERIAL, READER, PROTECTED, 1, 1000, address(executor));
        requestVm.startPrank(SOURCE_ACTOR);
        policyId = privacy.publishPolicy(APP, ROLE_SOURCE, _authority(ROLE_SOURCE), rules);
        privacy.openCase(CASE_ID, APP, policyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        for (uint256 i; i < 4; ++i) {
            privacy.setMember(CASE_ID, _persona(i), READER, 5000, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
            privacy.registerResource(
                _resource(i),
                CASE_ID,
                MATERIAL,
                keccak256(abi.encode("ciphertext", i)),
                ROLE_SOURCE,
                _authority(ROLE_SOURCE)
            );
        }
        requestVm.stopPrank();
    }

    function testControllerGrantsFourExplicitOrdinaryTuples() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(4);
        _batch(grants);
        for (uint256 i; i < grants.length; ++i) {
            require(privacy.canAccess(grants[i].resourceId, grants[i].persona, READER, PURPOSE), "grant missing");
            require(privacy.grantRevision(grants[i].resourceId, grants[i].persona, READER, PURPOSE) == 1, "revision");
        }
    }

    function testBatchMatchesSeparateGrantStateAndEachAccessConfiguredEvent() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(4);
        grants[0].expiresAt = 1400;
        grants[1].expiresAt = 1600;
        requestVm.prank(SOURCE_ACTOR);
        privacy.setMember(CASE_ID, _persona(1), READER, 4000, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
        uint256 snapshot = batchVm.snapshotState();
        batchVm.recordLogs();
        for (uint256 i; i < grants.length; ++i) {
            _single(grants[i]);
        }
        PrivacyBatchVm.Log[] memory separateLogs = batchVm.getRecordedLogs();
        bytes32[] memory beforeState = new bytes32[](grants.length);
        for (uint256 i; i < grants.length; ++i) {
            beforeState[i] = _tupleState(grants[i]);
        }
        require(batchVm.revertToState(snapshot), "restore failed");
        batchVm.recordLogs();
        _batch(grants);
        PrivacyBatchVm.Log[] memory batchLogs = batchVm.getRecordedLogs();
        require(batchLogs.length == 4, "one event per grant required");
        require(keccak256(abi.encode(batchLogs)) == keccak256(abi.encode(separateLogs)), "events differ");
        for (uint256 i; i < grants.length; ++i) {
            require(_tupleState(grants[i]) == beforeState[i], "grant state differs");
        }
    }

    function testInvalidLaterLeaseRollsBackEarlierGrantAndItsExistingRevision() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        grants[0].expiresAt = 1400;
        _single(grants[0]);
        bytes32 beforeState = _tupleState(grants[0]);
        grants[0].expiresAt = 1500;
        grants[1].expiresAt = 5001;
        requestVm.expectRevert();
        _batch(grants);
        require(_tupleState(grants[0]) == beforeState, "failed batch changed earlier grant");
        require(privacy.grantRevision(_resource(1), _persona(1), READER, PURPOSE) == 0, "later revision retained");
        grants[1].expiresAt = 1500;
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 2, "recovery revision");
        require(privacy.canAccess(_resource(1), _persona(1), READER, PURPOSE), "recovery grant");
    }

    function testEveryItemRequiresItsOwnApplicationCanonicalAuthority() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        bytes32 foreignResource = _foreignResource();
        grants[1].resourceId = foreignResource;
        requestVm.expectRevert();
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "cross-app partial grant");
        require(!privacy.canAccess(foreignResource, _persona(1), READER, PURPOSE), "foreign authority reused");
        grants[1].resourceId = _resource(1);
        _batch(grants);
        require(privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "local recovery");
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccess(
            foreignResource, _persona(1), READER, PURPOSE, 1500, ROLE_SOURCE, keccak256("privacy.batch.other-subject")
        );
        require(privacy.canAccess(foreignResource, _persona(1), READER, PURPOSE), "explicit foreign authority rejected");
    }

    function testCurrentPermissionAndCanonicalRotationRemainRequired() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        bytes32 grantAction = privacy.GRANT_ACCESS();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, grantAction, false);
        requestVm.expectRevert();
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "permission bypass");
        authorityMatrix.setPermission(APP, ROLE_SOURCE, grantAction, true);
        identitiesDeactivateAndRotate();
        requestVm.expectRevert();
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "stale authority bypass");
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccessMany(grants, ROLE_SOURCE, keccak256("privacy.batch.rotated"));
        require(privacy.canAccess(_resource(1), _persona(1), READER, PURPOSE), "rotated recovery");
    }

    function testProtectedLaterRuleCannotBeGrantedByControllerBatch() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        grants[1].purpose = PROTECTED;
        requestVm.expectRevert();
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "partial routine grant");
        require(privacy.grantRevision(_resource(1), _persona(1), READER, PROTECTED) == 0, "protected revision");
        require(!privacy.canAccess(_resource(1), _persona(1), READER, PROTECTED), "protected bypass");
        grants[1].purpose = PURPOSE;
        _batch(grants);
        require(privacy.canAccess(_resource(1), _persona(1), READER, PURPOSE), "ordinary recovery");
    }

    function testEmptyAndOversizedArraysRejectButAll64ItemsAreApplied() public {
        require(privacy.MAX_GRANTS() == 64, "batch bound");
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(0);
        batchVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, 0));
        _batch(grants);
        grants = _inputs(65);
        batchVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, 65));
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "invalid length mutated");
        grants = new AVAPrivacyRegistry.GrantInput[](64);
        AVAPrivacyRegistry.GrantInput memory item = _inputs(1)[0];
        for (uint256 i; i < 64; ++i) {
            grants[i] = item;
        }
        batchVm.recordLogs();
        _batch(grants);
        require(batchVm.getRecordedLogs().length == 64, "maximum batch omitted events");
        require(privacy.grantRevision(item.resourceId, item.persona, READER, PURPOSE) == 64, "maximum batch incomplete");
    }

    function testMembershipGenerationsRevokeRegrantAndExpiryStayTupleSpecific() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(4);
        _batch(grants);
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.setMember(CASE_ID, _persona(0), READER, 0, false, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.setMember(CASE_ID, _persona(0), READER, 5000, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.setMember(CASE_ID, _persona(1), READER, 6000, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();
        require(!privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "rejoin revived old grant");
        require(privacy.accessDeadline(_resource(1), _persona(1), READER, PURPOSE) == 0, "renewed generation retained");
        require(privacy.canAccess(_resource(2), _persona(2), READER, PURPOSE), "unrelated membership changed");
        _batch(_inputs(2));
        requestVm.prank(SOURCE_ACTOR);
        privacy.revokeAccess(_resource(0), _persona(0), READER, PURPOSE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(!privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "revocation ignored");
        require(privacy.canAccess(_resource(1), _persona(1), READER, PURPOSE), "other tuple revoked");
        AVAPrivacyRegistry.GrantInput[] memory regrant = _inputs(1);
        regrant[0].expiresAt = 1400;
        _batch(regrant);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 4, "revision history");
        requestVm.warp(1400);
        require(!privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "expiry boundary");
        require(privacy.canAccess(_resource(1), _persona(1), READER, PURPOSE), "other deadline changed");
    }

    function testStagingFuturePhaseDoesNotReleaseEarlyAndPhaseAdvanceClosesOldScope() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        grants[1].purpose = FUTURE;
        _batch(grants);
        require(privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "current phase grant");
        require(!privacy.canAccess(_resource(1), _persona(1), READER, FUTURE), "early future release");
        require(privacy.accessDeadline(_resource(1), _persona(1), READER, FUTURE) == 1500, "staged lease lost");
        requestVm.prank(SOURCE_ACTOR);
        privacy.advancePhase(CASE_ID, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(!privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "old phase leak");
        require(privacy.canAccess(_resource(1), _persona(1), READER, FUTURE), "future release absent");
    }

    function testInactiveResourceOrPolicyCannotPartiallyGrant() public {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(2);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(_resource(1), ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.expectRevert();
        _batch(grants);
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 0, "inactive resource partial");
        _batch(_inputs(1));
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivatePolicy(policyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.expectRevert();
        _batch(_inputs(1));
        require(privacy.grantRevision(_resource(0), _persona(0), READER, PURPOSE) == 1, "inactive policy mutated");
        require(!privacy.canAccess(_resource(0), _persona(0), READER, PURPOSE), "inactive policy access");
    }

    function testThreeSeparatePublicCallCost() public {
        _measure(3, false);
    }

    function testThreeBatchPublicCallCost() public {
        _measure(3, true);
    }

    function testFourSeparatePublicCallCost() public {
        _measure(4, false);
    }

    function testFourBatchPublicCallCost() public {
        _measure(4, true);
    }

    /// @dev Real public calls after the same fixture setup; intrinsic transaction gas and separate cold access excluded.
    function _measure(uint256 length, bool batch) private {
        AVAPrivacyRegistry.GrantInput[] memory grants = _inputs(length);
        uint256 totalGas;
        uint256 totalBytes;
        for (uint256 i; i < (batch ? 1 : length); ++i) {
            AVAPrivacyRegistry.GrantInput memory item = grants[i];
            bytes memory data = batch
                ? abi.encodeCall(privacy.grantAccessMany, (grants, ROLE_SOURCE, _authority(ROLE_SOURCE)))
                : abi.encodeCall(
                    privacy.grantAccess,
                    (
                        item.resourceId,
                        item.persona,
                        item.readerRole,
                        item.purpose,
                        item.expiresAt,
                        ROLE_SOURCE,
                        _authority(ROLE_SOURCE)
                    )
                );
            requestVm.prank(SOURCE_ACTOR);
            uint256 beforeGas = gasleft();
            (bool success,) = address(privacy).call(data);
            totalGas += beforeGas - gasleft();
            require(success, "measured grant failed");
            totalBytes += data.length;
        }
        emit log_named_uint("grant count", length);
        emit log_named_uint("warmed public call gas (no intrinsic)", totalGas);
        emit log_named_uint("calldata bytes", totalBytes);
        require(privacy.canAccess(_resource(length - 1), _persona(length - 1), READER, PURPOSE), "last grant missing");
    }

    function _foreignResource() private returns (bytes32 resourceId) {
        bytes32 otherApp = keccak256("privacy.batch.other-app");
        bytes32 otherAuthority = keccak256("privacy.batch.other-subject");
        bytes32 otherCase = keccak256("privacy.batch.other-case");
        resourceId = keccak256("privacy.batch.other-resource");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other.identity"), keccak256("other.authority"), address(this), "test:other-app"
        );
        identityRegistry.assignSubject(SOURCE_ACTOR, otherApp, ROLE_SOURCE, otherAuthority, "test:other-subject");
        authorityMatrix.setPermission(otherApp, ROLE_SOURCE, privacy.MANAGE_POLICY(), true);
        authorityMatrix.setPermission(otherApp, ROLE_SOURCE, privacy.MANAGE_CASE(), true);
        authorityMatrix.setPermission(otherApp, ROLE_SOURCE, privacy.REGISTER_RESOURCE(), true);
        authorityMatrix.setPermission(otherApp, ROLE_SOURCE, privacy.GRANT_ACCESS(), true);
        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](1);
        rules[0] = AVAPrivacyRegistry.Rule(MATERIAL, READER, PURPOSE, 1, 1000, address(0));
        requestVm.startPrank(SOURCE_ACTOR);
        uint256 otherPolicy = privacy.publishPolicy(otherApp, ROLE_SOURCE, otherAuthority, rules);
        privacy.openCase(otherCase, otherApp, otherPolicy, ROLE_SOURCE, otherAuthority);
        privacy.setMember(otherCase, _persona(1), READER, 5000, true, ROLE_SOURCE, otherAuthority);
        privacy.registerResource(
            resourceId, otherCase, MATERIAL, keccak256("foreign.ciphertext"), ROLE_SOURCE, otherAuthority
        );
        requestVm.stopPrank();
    }

    function identitiesDeactivateAndRotate() private {
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.assignSubject(
            SOURCE_ACTOR, APP, ROLE_SOURCE, keccak256("privacy.batch.rotated"), "test:rotated"
        );
    }

    function _tupleState(AVAPrivacyRegistry.GrantInput memory item) private view returns (bytes32) {
        (address executor, uint256 requestId, bytes32 effectHash) =
            privacy.accessBasis(item.resourceId, item.persona, item.readerRole, item.purpose);
        return keccak256(
            abi.encode(
                privacy.canAccess(item.resourceId, item.persona, item.readerRole, item.purpose),
                privacy.accessDeadline(item.resourceId, item.persona, item.readerRole, item.purpose),
                privacy.grantRevision(item.resourceId, item.persona, item.readerRole, item.purpose),
                executor,
                requestId,
                effectHash
            )
        );
    }

    function _single(AVAPrivacyRegistry.GrantInput memory item) private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccess(
            item.resourceId,
            item.persona,
            item.readerRole,
            item.purpose,
            item.expiresAt,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
    }

    function _batch(AVAPrivacyRegistry.GrantInput[] memory grants) private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccessMany(grants, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _inputs(uint256 length) private pure returns (AVAPrivacyRegistry.GrantInput[] memory grants) {
        grants = new AVAPrivacyRegistry.GrantInput[](length);
        for (uint256 i; i < length; ++i) {
            grants[i] = AVAPrivacyRegistry.GrantInput(_resource(i), _persona(i), READER, PURPOSE, 1500);
        }
    }

    function _resource(uint256 i) private pure returns (bytes32) {
        return keccak256(abi.encode("privacy.batch.resource", i));
    }

    function _persona(uint256 i) private pure returns (bytes32) {
        return keccak256(abi.encode("privacy.batch.persona", i));
    }
}
