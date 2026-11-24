// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAApplicationRegistry} from "../src/AVAApplicationRegistry.sol";
import {AVAIdentityRegistry} from "../src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "../src/core/AVAAuthorityMatrix.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";

interface AuthorityBatchVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function prank(address sender) external;
    function expectRevert(bytes calldata data) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory logs);
}

interface IExpectedSubjectAuthorization {
    function isAuthorisedSubject(
        address account,
        bytes32 appId,
        bytes32 roleKey,
        bytes32 actionKey,
        bytes32 authorityId
    ) external view returns (bool);
}

contract AuthorityBatchTest {
    AuthorityBatchVm private constant vm = AuthorityBatchVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant APP = keccak256("authority.batch.app");
    bytes32 private constant ROLE = keccak256("authority.batch.role");
    bytes32 private constant ACTION = keccak256("authority.batch.action");
    bytes32 private constant OTHER_ACTION = keccak256("authority.batch.other-action");
    bytes32 private constant SUBJECT = keccak256("authority.batch.subject");
    address private constant APP_ADMIN = address(0xA11);
    address private constant ACTOR = address(0xAC7);
    address private constant OUTSIDER = address(0xBAD);

    AVAApplicationRegistry private apps;
    AVAIdentityRegistry private identities;
    AVAAuthorityMatrix private matrix;

    function setUp() public {
        apps = new AVAApplicationRegistry(address(this));
        apps.registerApplication(APP, keccak256("identity"), keccak256("authority"), APP_ADMIN, "local:app");
        identities = new AVAIdentityRegistry(apps);
        identities.assignSubject(ACTOR, APP, ROLE, SUBJECT, "local:subject");
        matrix = new AVAAuthorityMatrix(apps, identities);
    }

    function testExpectedSubjectAuthorizationRefusesInvalidCurrentStateThenRecovers() public {
        IExpectedSubjectAuthorization query = IExpectedSubjectAuthorization(address(matrix));
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT), "permission absent");
        matrix.setPermission(APP, ROLE, ACTION, true);
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, bytes32(0)), "zero admitted");
        require(!query.isAuthorisedSubject(OUTSIDER, APP, ROLE, ACTION, SUBJECT), "outsider admitted");
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, keccak256("wrong")), "mismatch admitted");
        require(query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT), "grant rejected");
        matrix.setPermission(APP, ROLE, ACTION, false);
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT), "revocation missed");
        matrix.setPermission(APP, ROLE, ACTION, true);
        identities.deactivateSubject(SUBJECT);
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT), "inactive admitted");
        bytes32 replacement = keccak256("replacement canonical subject");
        identities.assignSubject(ACTOR, APP, ROLE, replacement, "local:replacement");
        require(!query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT), "old identity admitted");
        require(query.isAuthorisedSubject(ACTOR, APP, ROLE, ACTION, replacement), "replacement rejected");
    }

    function testBatchGrantAndRevokePreserveCanonicalAuthority() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](2);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        updates[1] = AVAAuthorityMatrix.PermissionUpdate(ROLE, OTHER_ACTION, true);
        vm.prank(APP_ADMIN);
        matrix.setPermissions(APP, updates);
        require(matrix.requireAuthorisedCanonicalSubject(ACTOR, APP, ROLE, ACTION) == SUBJECT, "canonical mismatch");
        require(
            matrix.requireAuthorisedSubject(ACTOR, APP, ROLE, OTHER_ACTION, SUBJECT) == SUBJECT, "second grant missing"
        );
        require(!matrix.isAuthorised(OUTSIDER, APP, ROLE, ACTION), "grant substituted for identity");

        updates[0].allowed = false;
        vm.prank(APP_ADMIN);
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "batch revoke unavailable");
        require(matrix.isAuthorised(ACTOR, APP, ROLE, OTHER_ACTION), "revoke changed another action");
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAuthorised.selector, ACTOR, ACTION));
        matrix.requireAuthorisedCanonicalSubject(ACTOR, APP, ROLE, ACTION);
    }

    function testInvalidItemRollsBackEarlierGrantsAndRevokesThenLegalBatchRecovers() public {
        matrix.setPermission(APP, ROLE, OTHER_ACTION, true);
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](3);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        updates[1] = AVAAuthorityMatrix.PermissionUpdate(ROLE, OTHER_ACTION, false);
        updates[2] = AVAAuthorityMatrix.PermissionUpdate(bytes32(0), ACTION, true);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.EmptyValue.selector));
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "invalid role retained earlier grant");
        require(matrix.isAuthorised(ACTOR, APP, ROLE, OTHER_ACTION), "invalid role retained earlier revoke");

        updates[2] = AVAAuthorityMatrix.PermissionUpdate(ROLE, bytes32(0), true);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.EmptyValue.selector));
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "invalid action retained earlier grant");
        require(matrix.isAuthorised(ACTOR, APP, ROLE, OTHER_ACTION), "invalid action retained earlier revoke");

        updates[2].actionKey = ACTION;
        matrix.setPermissions(APP, updates);
        require(matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "legal grant did not recover");
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, OTHER_ACTION), "legal revoke did not recover");
    }

    function testBatchEmitsOneOriginalEventPerItemInOrderIncludingFalseAndDuplicates() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](3);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        updates[1] = AVAAuthorityMatrix.PermissionUpdate(ROLE, OTHER_ACTION, true);
        updates[2] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, false);
        vm.recordLogs();
        matrix.setPermissions(APP, updates);
        AuthorityBatchVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 3, "wrong permission event count");
        _assertPermissionLog(logs[0], ACTION, true);
        _assertPermissionLog(logs[1], OTHER_ACTION, true);
        _assertPermissionLog(logs[2], ACTION, false);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "last duplicate did not win");
    }

    function testBatchRejectsZeroApplicationAndEmptyUpdates() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.EmptyValue.selector));
        matrix.setPermissions(bytes32(0), updates);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.EmptyValue.selector));
        matrix.setPermissions(APP, new AVAAuthorityMatrix.PermissionUpdate[](0));
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "invalid batch changed permission");
    }

    function testBatchRejectsUnknownApplication() public {
        bytes32 unknownApp = keccak256("unknown application");
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, uint256(unknownApp)));
        matrix.setPermissions(unknownApp, updates);
    }

    function testBatchUsesCurrentApplicationAdminAfterHandoverAndRevocation() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, OUTSIDER));
        vm.prank(OUTSIDER);
        matrix.setPermissions(APP, updates);
        apps.proposeApplicationAdmin(APP, OUTSIDER);
        vm.prank(OUTSIDER);
        apps.acceptApplicationAdmin(APP);
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, APP_ADMIN));
        vm.prank(APP_ADMIN);
        matrix.setPermissions(APP, updates);
        vm.prank(OUTSIDER);
        matrix.setPermissions(APP, updates);
        require(matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "current app admin rejected");

        apps.revokeApplicationAdmin(APP);
        updates[0].allowed = false;
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, OUTSIDER));
        vm.prank(OUTSIDER);
        matrix.setPermissions(APP, updates);
        require(matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "rejected admin changed permission");
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "root could not revoke");
    }

    function testBatchUsesCurrentRootAdminAfterHandover() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        apps.proposeAdmin(OUTSIDER);
        vm.prank(OUTSIDER);
        apps.acceptAdmin();
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, address(this)));
        matrix.setPermissions(APP, updates);
        vm.prank(OUTSIDER);
        matrix.setPermissions(APP, updates);
        require(matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "current root rejected");
        updates[0].allowed = false;
        vm.prank(APP_ADMIN);
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "root handover changed app admin authority");
    }

    function testBatchKeepsApplicationPermissionsAndCanonicalSubjectsSeparate() public {
        bytes32 otherApp = keccak256("other application");
        bytes32 otherSubject = keccak256("other canonical subject");
        apps.registerApplication(
            otherApp, keccak256("other identity"), keccak256("other authority"), OUTSIDER, "local:other"
        );
        identities.assignSubject(ACTOR, otherApp, ROLE, otherSubject, "local:other-subject");
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        vm.prank(APP_ADMIN);
        matrix.setPermissions(APP, updates);
        require(!matrix.isAuthorised(ACTOR, otherApp, ROLE, ACTION), "cross-app grant leaked");
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, APP_ADMIN));
        vm.prank(APP_ADMIN);
        matrix.setPermissions(otherApp, updates);
        matrix.setPermissions(otherApp, updates);
        require(
            matrix.requireAuthorisedCanonicalSubject(ACTOR, otherApp, ROLE, ACTION) == otherSubject,
            "other app canonical subject lost"
        );
        updates[0].allowed = false;
        matrix.setPermissions(APP, updates);
        require(matrix.isAuthorised(ACTOR, otherApp, ROLE, ACTION), "cross-app revoke leaked");
    }

    function testBatchGrantStillRequiresCurrentCanonicalSubject() public {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](1);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(ROLE, ACTION, true);
        matrix.setPermissions(APP, updates);
        identities.deactivateSubject(SUBJECT);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "inactive subject authorised");
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAuthorised.selector, ACTOR, ACTION));
        matrix.requireAuthorisedCanonicalSubject(ACTOR, APP, ROLE, ACTION);
        bytes32 replacement = keccak256("replacement canonical subject");
        identities.assignSubject(ACTOR, APP, ROLE, replacement, "local:replacement");
        require(matrix.requireAuthorisedCanonicalSubject(ACTOR, APP, ROLE, ACTION) == replacement, "identity cached");
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.SubjectMismatch.selector, replacement, SUBJECT));
        matrix.requireAuthorisedSubject(ACTOR, APP, ROLE, ACTION, SUBJECT);
    }

    function testStandaloneSetterRemainsAvailableAlongsideBatch() public {
        vm.prank(APP_ADMIN);
        matrix.setPermission(APP, ROLE, ACTION, true);
        require(
            matrix.requireAuthorisedCanonicalSubject(ACTOR, APP, ROLE, ACTION) == SUBJECT, "standalone grant missing"
        );
        vm.prank(APP_ADMIN);
        matrix.setPermission(APP, ROLE, ACTION, false);
        require(!matrix.isAuthorised(ACTOR, APP, ROLE, ACTION), "standalone revoke missing");
    }

    function _assertPermissionLog(AuthorityBatchVm.Log memory log, bytes32 action, bool allowed) private view {
        require(log.emitter == address(matrix), "wrong event emitter");
        require(log.topics.length == 4, "wrong event indexed fields");
        require(
            log.topics[0] == keccak256("PermissionConfigured(bytes32,bytes32,bytes32,bool)"), "wrong event signature"
        );
        require(log.topics[1] == APP && log.topics[2] == ROLE && log.topics[3] == action, "wrong event keys or order");
        require(abi.decode(log.data, (bool)) == allowed, "wrong event allowance");
    }
}
