// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAApplicationRegistry} from "../src/AVAApplicationRegistry.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAIdentityRegistry} from "../src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "../src/core/AVAAuthorityMatrix.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVADisclosurePolicyRegistry} from "../src/core/AVADisclosurePolicyRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVAWorkflowPolicyRouter} from "../src/core/AVAWorkflowPolicyRouter.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface AdministrationVm {
    function prank(address sender) external;
    function expectRevert(bytes calldata reason) external;
}

contract AdministrationBindingModule is RuleModuleIdentity {}

/// @dev All components are created by a factory, but management belongs to the explicit root.
contract AdministrationDeploymentFactory {
    function deploy(bytes memory initcode) external returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(initcode, 0x20), mload(initcode))
        }
        require(deployed.code.length != 0, "factory deployment failed");
    }
}

contract AdministrationSelfRootFactory {
    function deploy() external returns (AVAApplicationRegistry) {
        // A fresh contract's first CREATE uses nonce 1; the predicted child cannot administer itself.
        address child = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01")))));
        return new AVAApplicationRegistry(child);
    }
}

contract ProductionAdministrationTest is RequestAllocationFixture {
    AdministrationVm private constant adminVm =
        AdministrationVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant APP_A = keccak256("administration.app.a");
    bytes32 private constant APP_B = keccak256("administration.app.b");
    bytes32 private constant OBJECT = keccak256("administration.object");
    bytes32 private constant SUBJECT_B = keccak256("administration.subject.b");
    bytes32 private constant PACKAGE_SUBJECT_B = keccak256("administration.package.subject.b");
    address private constant MANAGER_A = address(0xD1);
    address private constant MANAGER_B = address(0xD2);
    address private constant NOMINEE = address(0xD3);
    address private constant REPLACEMENT = address(0xD4);
    address private constant ROOT_NEXT = address(0xD5);
    uint256 private packageB;
    AdministrationBindingModule private bindingModule;

    function setUp() public {
        _setUpRequestAllocation(APP_A, new M14PermissiveApplicationModule(APP_A), OBJECT);
        applicationRegistry.proposeApplicationAdmin(APP_A, MANAGER_A);
        adminVm.prank(MANAGER_A);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        applicationRegistry.registerApplication(
            APP_B, keccak256("b.identity"), keccak256("b.authority"), MANAGER_B, "test:b"
        );
        identityRegistry.assignSubject(SOURCE_ACTOR, APP_B, ROLE_SOURCE, SUBJECT_B, "test:b-source");
        identityRegistry.assignSubject(address(this), APP_B, ROLE_PACKAGE, PACKAGE_SUBJECT_B, "test:b-package");
        authorityMatrix.setPermission(APP_B, ROLE_PACKAGE, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, true);
        authorityMatrix.setPermission(APP_B, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        packageB = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP_B,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                PACKAGE_SUBJECT_B,
                1,
                keccak256("b.compatibility"),
                "test:b-rules"
            ),
            _coreBindings(new M14PermissiveApplicationModule(APP_B))
        );
        bindingModule = new AdministrationBindingModule();
    }

    function testFactoryInitializationUsesExplicitRootAcrossAllComponents() public {
        AdministrationDeploymentFactory factory = new AdministrationDeploymentFactory();
        AVAApplicationRegistry registry = AVAApplicationRegistry(
            factory.deploy(abi.encodePacked(type(AVAApplicationRegistry).creationCode, abi.encode(address(this))))
        );
        AVAIdentityRegistry identity = AVAIdentityRegistry(
            factory.deploy(abi.encodePacked(type(AVAIdentityRegistry).creationCode, abi.encode(registry)))
        );
        AVAAuthorityMatrix matrix = AVAAuthorityMatrix(
            factory.deploy(abi.encodePacked(type(AVAAuthorityMatrix).creationCode, abi.encode(registry, identity)))
        );
        AVACoreRulePackageRegistry packages = AVACoreRulePackageRegistry(
            factory.deploy(
                abi.encodePacked(type(AVACoreRulePackageRegistry).creationCode, abi.encode(registry, matrix))
            )
        );
        AVADisclosurePolicyRegistry disclosure = AVADisclosurePolicyRegistry(
            factory.deploy(
                abi.encodePacked(type(AVADisclosurePolicyRegistry).creationCode, abi.encode(registry, matrix))
            )
        );
        AVAEvidenceRegistry evidence = AVAEvidenceRegistry(
            factory.deploy(
                abi.encodePacked(
                    type(AVAEvidenceRegistry).creationCode, abi.encode(matrix, identity, packages, disclosure)
                )
            )
        );
        AVAWorkflowPolicyRouter router = AVAWorkflowPolicyRouter(
            factory.deploy(
                abi.encodePacked(type(AVAWorkflowPolicyRouter).creationCode, abi.encode(packages, evidence, disclosure))
            )
        );
        AVAGovernanceKernel factoryKernel = AVAGovernanceKernel(
            factory.deploy(
                abi.encodePacked(
                    type(AVAGovernanceKernel).creationCode,
                    abi.encode(matrix, identity, packages, evidence, disclosure, router)
                )
            )
        );
        require(registry.ADMIN() == address(this), "factory captured root");
        registry.registerApplication(
            APP_A, keccak256("factory.identity"), keccak256("factory.authority"), MANAGER_A, "test:factory"
        );
        identity.assignSubject(address(this), APP_A, ROLE_PACKAGE, PACKAGE_SUBJECT_B, "test:factory-package");
        matrix.setPermission(APP_A, ROLE_PACKAGE, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, true);
        uint256 packageId = packages.registerRulePackage(
            _corePackageInput(
                APP_A,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                PACKAGE_SUBJECT_B,
                1,
                keccak256("factory.compatibility"),
                "test:factory-rules"
            ),
            _coreBindings(new M14PermissiveApplicationModule(APP_A))
        );
        _expectNotAdmin(address(factory));
        registry.registerApplication(APP_B, keccak256("b"), keccak256("b"), MANAGER_B, "test:b");
        _expectNotAdmin(address(factory));
        identity.assignSubject(NOMINEE, APP_A, ROLE_SOURCE, SUBJECT_B, "test:factory-denied");
        _expectNotAdmin(address(factory));
        matrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        _expectNotAdmin(address(factory));
        factoryKernel.bindSourceBoundTransitionRequester(packageId, address(bindingModule));
        _expectNotAdmin(address(factory));
        factoryKernel.bindTransitionGuard(packageId, address(bindingModule));
        _expectNotAdmin(address(factory));
        factoryKernel.bindPostTransitionHook(packageId, address(bindingModule));
        factoryKernel.bindSourceBoundTransitionRequester(packageId, address(bindingModule));
        require(
            factoryKernel.sourceBoundTransitionRequesterByPackage(packageId) == address(bindingModule),
            "explicit root denied"
        );
    }

    function testInvalidInitialRootAndCodeLessRegistryAreRejected() public {
        _expectEmpty();
        new AVAApplicationRegistry(address(0));
        AdministrationSelfRootFactory factory = new AdministrationSelfRootFactory();
        _expectEmpty();
        factory.deploy();
        _expectEmpty();
        new AVAIdentityRegistry(AVAApplicationRegistry(address(0)));
        _expectEmpty();
        new AVAIdentityRegistry(AVAApplicationRegistry(NOMINEE));
    }

    function testInitialApplicationControllerMustBeExplicitAndExternal() public {
        _expectEmpty();
        applicationRegistry.registerApplication(
            keccak256("invalid.zero"), keccak256("identity"), keccak256("authority"), address(0), "test:invalid"
        );
        _expectEmpty();
        applicationRegistry.registerApplication(
            keccak256("invalid.self"),
            keccak256("identity"),
            keccak256("authority"),
            address(applicationRegistry),
            "test:invalid"
        );
    }

    function testInvalidRootAndApplicationNomineesAreRejected() public {
        address[3] memory invalidRoots = [address(0), address(applicationRegistry), address(this)];
        address[3] memory invalidManagers = [address(0), address(applicationRegistry), MANAGER_A];
        for (uint256 i; i < invalidRoots.length; ++i) {
            _expectEmpty();
            applicationRegistry.proposeAdmin(invalidRoots[i]);
            _expectEmpty();
            applicationRegistry.proposeApplicationAdmin(APP_A, invalidManagers[i]);
        }
    }

    function testManagerAssignsAndDeactivatesOnlyItsOwnApplicationSubjects() public {
        bytes32 subjectA = keccak256("manager.assigned.a");
        adminVm.prank(MANAGER_A);
        identityRegistry.assignSubject(NOMINEE, APP_A, ROLE_SOURCE, subjectA, "test:a-new");
        require(identityRegistry.hasRole(NOMINEE, APP_A, ROLE_SOURCE), "own assignment denied");
        _expectNotAdmin(MANAGER_A);
        identityRegistry.assignSubject(NOMINEE, APP_B, ROLE_SOURCE, keccak256("manager.denied.b"), "test:b-denied");
        _expectNotAdmin(MANAGER_A);
        identityRegistry.deactivateSubject(SUBJECT_B);
        adminVm.prank(MANAGER_A);
        identityRegistry.deactivateSubject(subjectA);
        require(!identityRegistry.getSubject(subjectA).active, "own deactivation denied");
        require(identityRegistry.getSubject(SUBJECT_B).active, "foreign subject changed");
    }

    function testManagerConfiguresPermissionsOnlyForItsApplication() public {
        adminVm.prank(MANAGER_A);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        require(
            !authorityMatrix.isAuthorised(SOURCE_ACTOR, APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "own permission unchanged"
        );
        _expectNotAdmin(MANAGER_A);
        authorityMatrix.setPermission(APP_B, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        require(
            authorityMatrix.isAuthorised(SOURCE_ACTOR, APP_B, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "foreign permission changed"
        );
    }

    function testAllPackageBindingsDeriveAuthorityFromVerifiedPackageApplication() public {
        _expectNotAdmin(MANAGER_A);
        kernel.bindSourceBoundTransitionRequester(packageB, address(bindingModule));
        _expectNotAdmin(MANAGER_A);
        kernel.bindTransitionGuard(packageB, address(bindingModule));
        _expectNotAdmin(MANAGER_A);
        kernel.bindPostTransitionHook(packageB, address(bindingModule));
        _bindAll(MANAGER_A, requestPackageId);
        _bindAll(MANAGER_B, packageB);
        require(
            kernel.sourceBoundTransitionRequesterByPackage(requestPackageId) == address(bindingModule),
            "requester missing"
        );
        require(address(kernel.transitionGuardByPackage(requestPackageId)) == address(bindingModule), "guard missing");
        require(address(kernel.postTransitionHookByPackage(packageB)) == address(bindingModule), "hook missing");
    }

    function testApplicationManagerCannotRegisterNamespacesOrOperateRootAdministration() public {
        _expectNotAdmin(MANAGER_A);
        applicationRegistry.registerApplication(
            keccak256("new.namespace"), keccak256("identity"), keccak256("authority"), MANAGER_A, "test:new"
        );
        _expectNotAdmin(MANAGER_A);
        applicationRegistry.proposeAdmin(NOMINEE);
        _expectNotAdmin(MANAGER_A);
        applicationRegistry.cancelAdminTransfer();
        _expectNotAdmin(MANAGER_A);
        applicationRegistry.revokeApplicationAdmin(APP_A);
        _expectNotAdmin(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_B, NOMINEE);
    }

    function testPendingRootHasNoManagementPowerAndOnlyNomineeCanAccept() public {
        applicationRegistry.proposeAdmin(ROOT_NEXT);
        _assertManagementDenied(ROOT_NEXT);
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptAdmin();
        require(applicationRegistry.ADMIN() == address(this), "proposal changed root");
        require(applicationRegistry.pendingAdmin() == ROOT_NEXT, "nomination lost");
        adminVm.prank(ROOT_NEXT);
        applicationRegistry.acceptAdmin();
        require(
            applicationRegistry.ADMIN() == ROOT_NEXT && applicationRegistry.pendingAdmin() == address(0),
            "acceptance missing"
        );
    }

    function testRootAcceptanceChangesIdentityMatrixAndKernelManagementDynamically() public {
        _rotateRoot(ROOT_NEXT);
        require(applicationRegistry.adminVersion() == 2, "root epoch unchanged");
        // The old root is not an application manager in this fixture.
        _assertManagementDenied(address(this));
        _expectNotAdmin(address(this));
        applicationRegistry.proposeAdmin(NOMINEE);
        adminVm.prank(ROOT_NEXT);
        identityRegistry.assignSubject(NOMINEE, APP_A, ROLE_SOURCE, keccak256("new.root.subject"), "test:new-root");
        adminVm.prank(ROOT_NEXT);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _bindAll(ROOT_NEXT, requestPackageId);
    }

    function testRootProposalReplacementAndCancellationInvalidatePreviousNominees() public {
        applicationRegistry.proposeAdmin(NOMINEE);
        applicationRegistry.proposeAdmin(ROOT_NEXT);
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptAdmin();
        applicationRegistry.cancelAdminTransfer();
        _expectNotAdmin(ROOT_NEXT);
        applicationRegistry.acceptAdmin();
        require(
            applicationRegistry.ADMIN() == address(this) && applicationRegistry.adminVersion() == 1,
            "cancel changed root"
        );
        applicationRegistry.proposeAdmin(ROOT_NEXT);
        adminVm.prank(ROOT_NEXT);
        applicationRegistry.acceptAdmin();
        _expectNotAdmin(ROOT_NEXT);
        applicationRegistry.acceptAdmin();
    }

    function testPendingApplicationManagerHasNoPowerAndOnlyNomineeCanAccept() public {
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        _assertManagementDenied(NOMINEE);
        _expectNotAdmin(REPLACEMENT);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        require(applicationRegistry.applicationAdmin(APP_A) == MANAGER_A, "proposal changed manager");
        adminVm.prank(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        _assertPendingCleared();
        require(applicationRegistry.applicationAdmin(APP_A) == NOMINEE, "nominee not installed");
    }

    function testApplicationAcceptanceImmediatelyRemovesPreviousManagementPowers() public {
        _rotateManager(NOMINEE);
        _assertManagementDenied(MANAGER_A);
        adminVm.prank(NOMINEE);
        identityRegistry.assignSubject(
            REPLACEMENT, APP_A, ROLE_SOURCE, keccak256("replacement.subject"), "test:replacement"
        );
        adminVm.prank(NOMINEE);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        adminVm.prank(NOMINEE);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _bindAll(NOMINEE, requestPackageId);
    }

    function testApplicationProposalReplacementAndCancellationInvalidateNominees() public {
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        applicationRegistry.proposeApplicationAdmin(APP_A, REPLACEMENT);
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        adminVm.prank(MANAGER_A);
        applicationRegistry.cancelApplicationAdminTransfer(APP_A);
        _assertPendingCleared();
        _expectNotAdmin(REPLACEMENT);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        require(applicationRegistry.applicationAdmin(APP_A) == MANAGER_A, "cancel changed manager");
    }

    function testRootRevocationClearsManagerAndPendingHandover() public {
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        applicationRegistry.revokeApplicationAdmin(APP_A);
        require(applicationRegistry.applicationAdmin(APP_A) == address(0), "manager survived revoke");
        _assertPendingCleared();
        _assertManagementDenied(MANAGER_A);
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
    }

    function testRootRotationInvalidatesPendingApplicationsButPreservesActiveManagers() public {
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        adminVm.prank(MANAGER_B);
        applicationRegistry.proposeApplicationAdmin(APP_B, REPLACEMENT);
        _rotateRoot(ROOT_NEXT);
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        _expectNotAdmin(REPLACEMENT);
        applicationRegistry.acceptApplicationAdmin(APP_B);
        require(applicationRegistry.applicationAdmin(APP_A) == MANAGER_A, "active a manager revoked");
        require(applicationRegistry.applicationAdmin(APP_B) == MANAGER_B, "active b manager revoked");
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        require(
            applicationRegistry.pendingApplicationAdminVersion(APP_A) == applicationRegistry.adminVersion(),
            "fresh epoch missing"
        );
        adminVm.prank(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
    }

    function testFuzzRootCyclingCannotReviveOldApplicationNomination(uint8 extraCycles) public {
        applicationRegistry.proposeApplicationAdmin(APP_A, NOMINEE);
        uint256 cycles = 1 + uint256(extraCycles % 4);
        for (uint256 i; i < cycles; ++i) {
            _rotateRoot(ROOT_NEXT);
            adminVm.prank(ROOT_NEXT);
            applicationRegistry.proposeAdmin(address(this));
            applicationRegistry.acceptAdmin();
        }
        require(applicationRegistry.ADMIN() == address(this), "root did not cycle");
        require(applicationRegistry.adminVersion() == 1 + cycles * 2, "epoch reused");
        _expectNotAdmin(NOMINEE);
        applicationRegistry.acceptApplicationAdmin(APP_A);
        require(applicationRegistry.applicationAdmin(APP_A) == MANAGER_A, "stale manager accepted");
    }

    function testRootCanRecoverRevokedApplicationAndAppRolesRemainIndependent() public {
        applicationRegistry.revokeApplicationAdmin(APP_A);
        identityRegistry.assignSubject(NOMINEE, APP_A, ROLE_SOURCE, keccak256("recovery.subject"), "test:recovery");
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _bindAll(address(this), requestPackageId);
        applicationRegistry.proposeApplicationAdmin(APP_A, address(this));
        applicationRegistry.acceptApplicationAdmin(APP_A);
        _rotateRoot(ROOT_NEXT);
        // An explicit application-manager assignment survives loss of the independent root role.
        identityRegistry.deactivateSubject(keccak256("recovery.subject"));
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        _expectNotAdmin(address(this));
        authorityMatrix.setPermission(APP_B, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _expectNotAdmin(address(this));
        applicationRegistry.proposeAdmin(NOMINEE);
    }

    function testBusinessDelegateSurvivesManagementRotationAndRevocation() public {
        _rotateManager(NOMINEE);
        _rotateRoot(ROOT_NEXT);
        adminVm.prank(ROOT_NEXT);
        applicationRegistry.revokeApplicationAdmin(APP_A);
        require(
            identityRegistry.subjectOf(SOURCE_ACTOR, APP_A, ROLE_SOURCE) == _authority(ROLE_SOURCE),
            "business identity changed"
        );
        require(
            authorityMatrix.isAuthorised(
                SOURCE_ACTOR, APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_DISCLOSURE_POLICY
            ),
            "business permission revoked"
        );
        adminVm.prank(SOURCE_ACTOR);
        uint256 policyId = disclosureRegistry.registerPolicy(
            APP_A,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            keccak256("after.management.change"),
            "Still delegated",
            "test:still-delegated"
        );
        require(disclosureRegistry.getPolicy(policyId).registeredBy == SOURCE_ACTOR, "business action denied");
    }

    function testExplicitPermissionToggleIsReversibleAndApplicationScoped() public {
        adminVm.prank(MANAGER_A);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        require(
            !authorityMatrix.isAuthorised(SOURCE_ACTOR, APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "permission not revoked"
        );
        require(identityRegistry.getSubject(_authority(ROLE_SOURCE)).active, "permission toggle deactivated subject");
        require(
            authorityMatrix.isAuthorised(SOURCE_ACTOR, APP_B, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "foreign grant lost"
        );
        adminVm.prank(MANAGER_A);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        require(
            authorityMatrix.isAuthorised(SOURCE_ACTOR, APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "permission not restored"
        );
    }

    function testSealedBindingsCannotRotateEvenAfterRootAndManagerHandover() public {
        _bindAll(MANAGER_A, requestPackageId);
        _rotateManager(NOMINEE);
        _rotateRoot(ROOT_NEXT);
        _assertBindingSealed(NOMINEE, requestPackageId);
        _assertBindingSealed(ROOT_NEXT, requestPackageId);
        require(
            kernel.sourceBoundTransitionRequesterByPackage(requestPackageId) == address(bindingModule),
            "requester changed"
        );
        require(address(kernel.transitionGuardByPackage(requestPackageId)) == address(bindingModule), "guard changed");
        require(address(kernel.postTransitionHookByPackage(requestPackageId)) == address(bindingModule), "hook changed");
    }

    function testUseStartedPreventsFirstBindingEvenForNewRoot() public {
        _createStateForCommitment(keccak256("administration.pre-use.guard"));
        require(kernel.recognisedStateUseStartedByPackage(requestPackageId), "use not started");
        _rotateRoot(ROOT_NEXT);
        _assertBindingSealed(ROOT_NEXT, requestPackageId);
        require(
            kernel.sourceBoundTransitionRequesterByPackage(requestPackageId) == address(0), "late requester installed"
        );
        require(address(kernel.transitionGuardByPackage(requestPackageId)) == address(0), "late guard installed");
        require(address(kernel.postTransitionHookByPackage(requestPackageId)) == address(0), "late hook installed");
    }

    function _rotateRoot(address next) private {
        applicationRegistry.proposeAdmin(next);
        adminVm.prank(next);
        applicationRegistry.acceptAdmin();
    }

    function _rotateManager(address next) private {
        adminVm.prank(MANAGER_A);
        applicationRegistry.proposeApplicationAdmin(APP_A, next);
        adminVm.prank(next);
        applicationRegistry.acceptApplicationAdmin(APP_A);
    }

    function _bindAll(address actor, uint256 packageId) private {
        adminVm.prank(actor);
        kernel.bindSourceBoundTransitionRequester(packageId, address(bindingModule));
        adminVm.prank(actor);
        kernel.bindTransitionGuard(packageId, address(bindingModule));
        adminVm.prank(actor);
        kernel.bindPostTransitionHook(packageId, address(bindingModule));
    }

    function _assertBindingSealed(address actor, uint256 packageId) private {
        adminVm.prank(actor);
        adminVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, packageId));
        kernel.bindSourceBoundTransitionRequester(packageId, address(bindingModule));
        adminVm.prank(actor);
        adminVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, packageId));
        kernel.bindTransitionGuard(packageId, address(bindingModule));
        adminVm.prank(actor);
        adminVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, packageId));
        kernel.bindPostTransitionHook(packageId, address(bindingModule));
    }

    function _assertManagementDenied(address actor) private {
        _expectNotAdmin(actor);
        identityRegistry.assignSubject(
            REPLACEMENT, APP_A, ROLE_SOURCE, keccak256("unauthorised.subject"), "test:denied"
        );
        _expectNotAdmin(actor);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        _expectNotAdmin(actor);
        authorityMatrix.setPermission(APP_A, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _expectNotAdmin(actor);
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(bindingModule));
        _expectNotAdmin(actor);
        kernel.bindTransitionGuard(requestPackageId, address(bindingModule));
        _expectNotAdmin(actor);
        kernel.bindPostTransitionHook(requestPackageId, address(bindingModule));
        _expectNotAdmin(actor);
        applicationRegistry.proposeApplicationAdmin(APP_A, REPLACEMENT);
        _expectNotAdmin(actor);
        applicationRegistry.cancelApplicationAdminTransfer(APP_A);
    }

    function _assertPendingCleared() private view {
        require(applicationRegistry.pendingApplicationAdmin(APP_A) == address(0), "pending manager remains");
        require(applicationRegistry.pendingApplicationAdminVersion(APP_A) == 0, "pending epoch remains");
    }

    function _expectNotAdmin(address actor) private {
        adminVm.prank(actor);
        adminVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.NotAdmin.selector, actor));
    }

    function _expectEmpty() private {
        adminVm.expectRevert(abi.encodeWithSelector(AVACoreTypes.EmptyValue.selector));
    }
}
