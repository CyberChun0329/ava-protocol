// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAApplicationRegistry} from "../src/AVAApplicationRegistry.sol";
import {AVAIdentityRegistry} from "../src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "../src/core/AVAAuthorityMatrix.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAPrivacyRegistry} from "../src/extensions/privacy/AVAPrivacyRegistry.sol";

interface PrivacyVm {
    function prank(address sender) external;
    function expectRevert() external;
    function expectRevert(bytes calldata data) external;
    function warp(uint256 timestamp) external;
}

contract PrivacyRegistryTest {
    PrivacyVm private constant vm = PrivacyVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant APP = keccak256("privacy.test.app");
    bytes32 private constant OTHER_APP = keccak256("privacy.test.other-app");
    bytes32 private constant MANAGER_ROLE = keccak256("privacy.test.manager");
    bytes32 private constant AUTHORITY_ID = keccak256("privacy.test.authority");
    bytes32 private constant OTHER_AUTHORITY_ID = keccak256("privacy.test.other-authority");
    bytes32 private constant CASE_ID = keccak256("privacy.test.case");
    bytes32 private constant SECOND_CASE = keccak256("privacy.test.second-case");
    bytes32 private constant RESOURCE = keccak256("privacy.test.resource");
    bytes32 private constant SECOND_RESOURCE = keccak256("privacy.test.second-resource");
    bytes32 private constant MATERIAL = keccak256("privacy.test.material");
    bytes32 private constant READER = keccak256("privacy.test.reader");
    bytes32 private constant EDITOR = keccak256("privacy.test.editor");
    bytes32 private constant REVIEW = keccak256("privacy.test.review-purpose");
    bytes32 private constant AUDIT = keccak256("privacy.test.audit-purpose");
    // Synthetic opaque fixture; no reader account or real identity is registered.
    bytes32 private constant PERSONA = keccak256("privacy.test.random-persona");
    bytes32 private constant CIPHERTEXT_HASH = keccak256("synthetic ciphertext bytes");
    address private constant MANAGER = address(0xA11CE);
    address private constant OTHER_MANAGER = address(0xB0B);
    AVAApplicationRegistry private apps;
    AVAIdentityRegistry private identities;
    AVAAuthorityMatrix private matrix;
    AVAPrivacyRegistry private privacy;
    uint256 private policyId;

    function setUp() public {
        vm.warp(1000);
        apps = new AVAApplicationRegistry(address(this));
        apps.registerApplication(APP, keccak256("app-id"), keccak256("app-admin"), address(this), "test:app");
        apps.registerApplication(
            OTHER_APP, keccak256("other-id"), keccak256("other-admin"), address(this), "test:other-app"
        );
        identities = new AVAIdentityRegistry(apps);
        matrix = new AVAAuthorityMatrix(apps, identities);
        privacy = new AVAPrivacyRegistry(matrix);
        identities.assignSubject(MANAGER, APP, MANAGER_ROLE, AUTHORITY_ID, "test:manager");
        identities.assignSubject(OTHER_MANAGER, OTHER_APP, MANAGER_ROLE, OTHER_AUTHORITY_ID, "test:other");
        _permissions(APP, true);
        _permissions(OTHER_APP, true);
        AVAPrivacyRegistry.Rule[] memory rules = _rules();
        vm.prank(MANAGER);
        policyId = privacy.publishPolicy(APP, MANAGER_ROLE, AUTHORITY_ID, rules);
        vm.prank(MANAGER);
        privacy.openCase(CASE_ID, APP, policyId, MANAGER_ROLE, AUTHORITY_ID);
        _member(CASE_ID, READER, 5000, true);
        _member(CASE_ID, EDITOR, 5000, true);
        _resource(RESOURCE, CASE_ID);
        _resource(SECOND_RESOURCE, CASE_ID);
    }

    function testDefaultDenyAndNoRootBusinessBypass() public {
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "ungranted access");
        require(!privacy.canAccess(bytes32(0), PERSONA, READER, REVIEW), "unknown access");
        vm.expectRevert();
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1500, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        privacy.publishPolicy(APP, MANAGER_ROLE, AUTHORITY_ID, _rules());
        vm.expectRevert();
        privacy.setMember(CASE_ID, PERSONA, READER, 2000, true, MANAGER_ROLE, AUTHORITY_ID);
        require(!privacy.canAccess(RESOURCE, bytes32(uint256(uint160(address(this)))), READER, REVIEW), "root read");
        _grant(RESOURCE, READER, REVIEW, 1500);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "explicit lease missing");
    }

    function testDeliveryDeadlineTracksGrantAndMembershipGeneration() public {
        vm.prank(MANAGER);
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1500, MANAGER_ROLE, AUTHORITY_ID);
        require(privacy.membershipDeadline(CASE_ID, PERSONA, READER) == 5000, "member deadline");
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, REVIEW) == 1500, "grant deadline");
        _member(CASE_ID, READER, 1400, true);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, REVIEW) == 0, "stale generation deadline");
        vm.prank(MANAGER);
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1300, MANAGER_ROLE, AUTHORITY_ID);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, REVIEW) == 1300, "renewed grant");
        vm.prank(MANAGER);
        privacy.revokeAccess(RESOURCE, PERSONA, READER, REVIEW, MANAGER_ROLE, AUTHORITY_ID);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, REVIEW) == 0, "revoked grant");
    }

    function testResourceRolePurposeAndPhaseAreIndependent() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "review lease");
        require(!privacy.canAccess(SECOND_RESOURCE, PERSONA, READER, REVIEW), "cross resource");
        require(!privacy.canAccess(RESOURCE, PERSONA, EDITOR, REVIEW), "cross role");
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, AUDIT), "cross purpose");
        _grant(RESOURCE, READER, AUDIT, 1500);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, AUDIT), "early release");
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 1, MANAGER_ROLE, AUTHORITY_ID);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, AUDIT), "phase release missing");
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "old phase leak");
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 31, MANAGER_ROLE, AUTHORITY_ID);
        _grant(RESOURCE, EDITOR, AUDIT, 1500);
        require(privacy.canAccess(RESOURCE, PERSONA, EDITOR, AUDIT), "phase31 shift");
    }

    function testExpiryIsStrictAndCannotExceedMembershipOrRule() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        vm.warp(1499);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "premature expiry");
        vm.warp(1500);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "expiry boundary");
        _member(CASE_ID, READER, 1600, true);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1601);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1500);
        _grant(RESOURCE, READER, REVIEW, 1600);
        vm.warp(1600);
        require(!privacy.isMember(CASE_ID, PERSONA, READER), "member expiry boundary");
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "member expiry access");
        _member(CASE_ID, READER, 5000, true);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 2601);
        _grant(RESOURCE, READER, REVIEW, 2600);
    }

    function testLeaveRejoinAndRenewalNeverReviveOldGrants() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        _grant(SECOND_RESOURCE, READER, REVIEW, 1500);
        _member(CASE_ID, READER, 0, false);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "removed member");
        _member(CASE_ID, READER, 5000, true);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "rejoin revival");
        _grant(RESOURCE, READER, REVIEW, 1500);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "fresh regrant");
        require(!privacy.canAccess(SECOND_RESOURCE, PERSONA, READER, REVIEW), "other lease revived");
        _member(CASE_ID, READER, 6000, true);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "renewal revival");
        _member(CASE_ID, READER, 1100, true);
        _grant(RESOURCE, READER, REVIEW, 1100);
        vm.warp(1100);
        _member(CASE_ID, READER, 6000, true);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "expired renewal revival");
    }

    function testRevokeAndRegrantOnlyRestoreExactTuple() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        _grant(SECOND_RESOURCE, READER, REVIEW, 1500);
        _revoke(RESOURCE, READER, REVIEW);
        _revoke(SECOND_RESOURCE, READER, REVIEW);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "revoked access");
        _grant(RESOURCE, READER, REVIEW, 1400);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "regrant missing");
        require(!privacy.canAccess(SECOND_RESOURCE, PERSONA, READER, REVIEW), "revoked tuple revived");
        vm.warp(1400);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "old longer grant revived");
    }

    function testOtherCaseMembershipCannotOpenResource() public {
        vm.prank(MANAGER);
        privacy.openCase(SECOND_CASE, APP, policyId, MANAGER_ROLE, AUTHORITY_ID);
        _resource(keccak256("different-case-resource"), SECOND_CASE);
        _expectGrantRevert(keccak256("different-case-resource"), READER, REVIEW, 1500);
        _member(SECOND_CASE, READER, 5000, true);
        _grant(RESOURCE, READER, REVIEW, 1500);
        require(!privacy.canAccess(keccak256("different-case-resource"), PERSONA, READER, REVIEW), "case leak");
    }

    function testOtherAppAuthorityAndPolicyDenied() public {
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.openCase(SECOND_CASE, OTHER_APP, policyId, MANAGER_ROLE, OTHER_AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1500, MANAGER_ROLE, OTHER_AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.setMember(CASE_ID, PERSONA, READER, 2000, true, MANAGER_ROLE, OTHER_AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.deactivatePolicy(policyId, MANAGER_ROLE, OTHER_AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.registerResource(
            keccak256("foreign"), CASE_ID, MATERIAL, CIPHERTEXT_HASH, MANAGER_ROLE, OTHER_AUTHORITY_ID
        );
    }

    function testPermissionRevocationAndCanonicalRotationGateMutations() public {
        matrix.setPermission(APP, MANAGER_ROLE, privacy.GRANT_ACCESS(), false);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1500);
        matrix.setPermission(APP, MANAGER_ROLE, privacy.GRANT_ACCESS(), true);
        identities.deactivateSubject(AUTHORITY_ID);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1500);
        bytes32 rotated = keccak256("rotated-manager");
        identities.assignSubject(MANAGER, APP, MANAGER_ROLE, rotated, "test:rotated");
        vm.expectRevert(abi.encodeWithSelector(AVACoreTypes.SubjectMismatch.selector, rotated, AUTHORITY_ID));
        vm.prank(MANAGER);
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1500, MANAGER_ROLE, AUTHORITY_ID);
        vm.prank(MANAGER);
        privacy.grantAccess(RESOURCE, PERSONA, READER, REVIEW, 1500, MANAGER_ROLE, rotated);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "rotated authority unusable");
    }

    function testEachManagementActionUsesItsOwnPermission() public {
        matrix.setPermission(APP, MANAGER_ROLE, privacy.MANAGE_POLICY(), false);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.deactivatePolicy(policyId, MANAGER_ROLE, AUTHORITY_ID);
        matrix.setPermission(APP, MANAGER_ROLE, privacy.MANAGE_CASE(), false);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 1, MANAGER_ROLE, AUTHORITY_ID);
        matrix.setPermission(APP, MANAGER_ROLE, privacy.REGISTER_RESOURCE(), false);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.deactivateResource(RESOURCE, MANAGER_ROLE, AUTHORITY_ID);
        _grant(RESOURCE, READER, REVIEW, 1500);
    }

    function testResourceDeactivationIsIrreversibleAndContextRetained() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        vm.prank(MANAGER);
        privacy.deactivateResource(RESOURCE, MANAGER_ROLE, AUTHORITY_ID);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "deactivated access");
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1500);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.registerResource(RESOURCE, CASE_ID, MATERIAL, CIPHERTEXT_HASH, MANAGER_ROLE, AUTHORITY_ID);
        (bytes32 appId, bytes32 caseId, uint256 id, bytes32 material, bytes32 ciphertextHash, bool active) =
            privacy.resourceContext(RESOURCE);
        require(appId == APP && caseId == CASE_ID && id == policyId, "lost binding");
        require(material == MATERIAL && ciphertextHash == CIPHERTEXT_HASH && !active, "lost context");
    }

    function testRegisterResourcePairChecksCaseAuthorityAndRollsBackBothEntries() public {
        bytes32 first = keccak256("new first resource");
        bytes32 second = keccak256("new second resource");
        AVAPrivacyRegistry.ResourceRegistration[2] memory pair = [
            AVAPrivacyRegistry.ResourceRegistration(first, MATERIAL, CIPHERTEXT_HASH),
            AVAPrivacyRegistry.ResourceRegistration(second, keccak256("separate audience"), keccak256("second ciphertext"))
        ];
        vm.expectRevert();
        vm.prank(OTHER_MANAGER);
        privacy.registerResourcePair(CASE_ID, pair, MANAGER_ROLE, OTHER_AUTHORITY_ID);
        pair[1].resourceId = RESOURCE;
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.registerResourcePair(CASE_ID, pair, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        privacy.resourceContext(first);

        pair[1].resourceId = second;
        vm.prank(MANAGER);
        privacy.registerResourcePair(CASE_ID, pair, MANAGER_ROLE, AUTHORITY_ID);
        for (uint256 i; i < 2; ++i) {
            (bytes32 appId, bytes32 caseId, uint256 id, bytes32 material, bytes32 ciphertextHash, bool active) =
                privacy.resourceContext(pair[i].resourceId);
            require(appId == APP && caseId == CASE_ID && id == policyId && active, "wrong case");
            require(material == pair[i].materialClass && ciphertextHash == pair[i].ciphertextHash, "wrong material");
        }
    }

    function testPolicyImmutableAndDeactivationFailsClosedForAllCases() public {
        _grant(RESOURCE, READER, REVIEW, 1500);
        vm.prank(MANAGER);
        privacy.openCase(SECOND_CASE, APP, policyId, MANAGER_ROLE, AUTHORITY_ID);
        bytes32 third = keccak256("policy-second-case-resource");
        _member(SECOND_CASE, READER, 5000, true);
        _resource(third, SECOND_CASE);
        _grant(third, READER, REVIEW, 1500);
        AVAPrivacyRegistry.Rule[] memory replacement = _rules();
        replacement[0].maxLeaseSeconds = 500;
        vm.prank(MANAGER);
        uint256 newer = privacy.publishPolicy(APP, MANAGER_ROLE, AUTHORITY_ID, replacement);
        require(newer != policyId && privacy.getPolicyRules(policyId)[0].maxLeaseSeconds == 1000, "policy mutated");
        vm.prank(MANAGER);
        privacy.deactivatePolicy(policyId, MANAGER_ROLE, AUTHORITY_ID);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, REVIEW), "policy deactivate leak");
        require(!privacy.canAccess(third, PERSONA, READER, REVIEW), "second case leak");
        (bytes32 appId, bool active) = privacy.policyContext(policyId);
        require(appId == APP && !active && privacy.getPolicyRules(policyId).length == 3, "policy lost");
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.openCase(keccak256("late case"), APP, policyId, MANAGER_ROLE, AUTHORITY_ID);
        _expectGrantRevert(RESOURCE, READER, REVIEW, 1500);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.deactivatePolicy(policyId, MANAGER_ROLE, AUTHORITY_ID);
    }

    function testInvalidRulesAndBoundedCount() public {
        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](0);
        _expectPolicyRevert(rules);
        rules = new AVAPrivacyRegistry.Rule[](65);
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[0].phaseMask = 0;
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[0].maxLeaseSeconds = 0;
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[0].materialClass = bytes32(0);
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[0].readerRole = bytes32(0);
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[0].purpose = bytes32(0);
        _expectPolicyRevert(rules);
        rules = _rules();
        rules[1] = rules[0];
        rules[1].phaseMask = 2;
        _expectPolicyRevert(rules);
        require(privacy.nextPolicyId() == 2, "failed publish changed state");
    }

    function testInvalidMembershipPhaseResourceAndUnknownReferences() public {
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.setMember(CASE_ID, bytes32(0), READER, 2000, true, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.setMember(CASE_ID, PERSONA, READER, 1000, true, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.setMember(CASE_ID, PERSONA, READER, 2000, false, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 32, MANAGER_ROLE, AUTHORITY_ID);
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 2, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.advancePhase(CASE_ID, 1, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.registerResource(bytes32(0), CASE_ID, MATERIAL, CIPHERTEXT_HASH, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.registerResource(keccak256("zero hash"), CASE_ID, MATERIAL, bytes32(0), MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.openCase(CASE_ID, APP, policyId, MANAGER_ROLE, AUTHORITY_ID);
        vm.expectRevert();
        privacy.resourceContext(bytes32(0));
        vm.expectRevert();
        privacy.caseContext(bytes32(0));
        vm.expectRevert();
        privacy.policyContext(0);
        (bytes32 appId, uint256 id, uint8 phase) = privacy.caseContext(CASE_ID);
        require(appId == APP && id == policyId && phase == 2, "case context");
    }

    function testUnknownMaterialRolePurposeAndZeroPersonaDenied() public {
        _expectGrantRevert(RESOURCE, EDITOR, REVIEW, 1500);
        _expectGrantRevert(RESOURCE, READER, keccak256("unspecified purpose"), 1500);
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.grantAccess(RESOURCE, bytes32(0), READER, REVIEW, 1500, MANAGER_ROLE, AUTHORITY_ID);
        vm.prank(MANAGER);
        privacy.registerResource(
            keccak256("unsupported material"),
            CASE_ID,
            keccak256("no rule"),
            CIPHERTEXT_HASH,
            MANAGER_ROLE,
            AUTHORITY_ID
        );
        _expectGrantRevert(keccak256("unsupported material"), READER, REVIEW, 1500);
    }

    function _rules() private pure returns (AVAPrivacyRegistry.Rule[] memory rules) {
        rules = new AVAPrivacyRegistry.Rule[](3);
        rules[0] = AVAPrivacyRegistry.Rule(MATERIAL, READER, REVIEW, 1, 1000, address(0));
        rules[1] = AVAPrivacyRegistry.Rule(MATERIAL, READER, AUDIT, 2, 1000, address(0));
        rules[2] = AVAPrivacyRegistry.Rule(MATERIAL, EDITOR, AUDIT, uint32(1) << 31, 1000, address(0));
    }

    function _permissions(bytes32 appId, bool allowed) private {
        matrix.setPermission(appId, MANAGER_ROLE, privacy.MANAGE_POLICY(), allowed);
        matrix.setPermission(appId, MANAGER_ROLE, privacy.MANAGE_CASE(), allowed);
        matrix.setPermission(appId, MANAGER_ROLE, privacy.REGISTER_RESOURCE(), allowed);
        matrix.setPermission(appId, MANAGER_ROLE, privacy.GRANT_ACCESS(), allowed);
    }

    function _member(bytes32 caseId, bytes32 readerRole, uint64 expiresAt, bool enabled) private {
        vm.prank(MANAGER);
        privacy.setMember(caseId, PERSONA, readerRole, expiresAt, enabled, MANAGER_ROLE, AUTHORITY_ID);
    }

    function _resource(bytes32 resourceId, bytes32 caseId) private {
        vm.prank(MANAGER);
        privacy.registerResource(resourceId, caseId, MATERIAL, CIPHERTEXT_HASH, MANAGER_ROLE, AUTHORITY_ID);
    }

    function _grant(bytes32 resourceId, bytes32 readerRole, bytes32 purpose, uint64 expiresAt) private {
        vm.prank(MANAGER);
        privacy.grantAccess(resourceId, PERSONA, readerRole, purpose, expiresAt, MANAGER_ROLE, AUTHORITY_ID);
    }

    function _revoke(bytes32 resourceId, bytes32 readerRole, bytes32 purpose) private {
        vm.prank(MANAGER);
        privacy.revokeAccess(resourceId, PERSONA, readerRole, purpose, MANAGER_ROLE, AUTHORITY_ID);
    }

    function _expectGrantRevert(bytes32 resourceId, bytes32 readerRole, bytes32 purpose, uint64 expiresAt) private {
        vm.expectRevert();
        _grant(resourceId, readerRole, purpose, expiresAt);
    }

    function _expectPolicyRevert(AVAPrivacyRegistry.Rule[] memory rules) private {
        vm.expectRevert();
        vm.prank(MANAGER);
        privacy.publishPolicy(APP, MANAGER_ROLE, AUTHORITY_ID, rules);
    }
}
