// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkOrder, WorkOrderModule} from "../src/WorkOrder.sol";
import {AVACoreTypes} from "@ava-protocol/contracts/src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "@ava-protocol/contracts/src/core/AVACapabilityKeys.sol";
import {AVAGovernanceKernel} from "@ava-protocol/contracts/src/core/AVAGovernanceKernel.sol";
import {AVAIdentityRegistry} from "@ava-protocol/contracts/src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "@ava-protocol/contracts/src/core/AVAAuthorityMatrix.sol";
import {AVACoreRulePackageRegistry} from "@ava-protocol/contracts/src/core/AVACoreRulePackageRegistry.sol";
import {IAVAApplicationModule} from "@ava-protocol/contracts/src/interfaces/IAVAApplicationModule.sol";
import {IRuleModuleIdentity, RuleModuleIdentity} from "@ava-protocol/contracts/src/interfaces/IRuleModuleIdentity.sol";
import {AVAChallengeExtension} from "@ava-protocol/contracts/src/extensions/challenge/AVAChallengeExtension.sol";
import {AVARecognisedRuleGovernance} from "@ava-protocol/contracts/src/extensions/governance/AVARecognisedRuleGovernance.sol";
import {AVALocalRuleRevisionPolicy} from "@ava-protocol/contracts/src/extensions/governance/AVALocalRuleRevisionPolicy.sol";

interface RuleLifecycleVm {
    function startBroadcast(address) external;
    function stopBroadcast() external;
}

/// @notice Close new WorkOrder intake while preserving evidence admission for historical corrections.
contract RetiredWorkOrderModule is WorkOrderModule {
    error WorkOrderIntakeClosed();

    function validateGovernedObject(GovernedObjectContext calldata) external pure override {
        revert WorkOrderIntakeClosed();
    }
}

/// @notice Narrow application semantics for a WorkOrder rule revision proposal.
contract WorkOrderGovernanceModule is IAVAApplicationModule, RuleModuleIdentity {
    bytes32 private constant GOVERNANCE_WORKFLOW = keccak256("independent.work-order.governance.v1");
    bytes32 private constant PROPOSAL = keccak256("ava.rule-revision.proposal.v1");

    function applicationId() external pure returns (bytes32) { return WorkOrder.APP; }

    function validateGovernedObject(GovernedObjectContext calldata c) external pure {
        require(c.appId == WorkOrder.APP && c.workflowKey == GOVERNANCE_WORKFLOW && c.objectTypeKey == PROPOSAL
            && c.roleKey == WorkOrder.REQUESTER && c.parentObjectId == 0, "Invalid proposal");
    }

    function validateEvidence(EvidenceContext calldata c) external pure {
        require(c.appId == WorkOrder.APP && c.workflowKey == GOVERNANCE_WORKFLOW && c.roleKey == WorkOrder.REQUESTER,
            "Requester evidence required");
    }

    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata c) external pure {
        require(c.appId == WorkOrder.APP && c.workflowKey == GOVERNANCE_WORKFLOW && c.objectTypeKey == PROPOSAL
            && c.roleKey == WorkOrder.INSPECTOR && c.stage == AVACoreTypes.Stage.Verification
            && c.status == AVACoreTypes.RecognisedStateStatus.Provisional, "Inspector recognition required");
    }

    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata c) external pure {
        require(c.appId == WorkOrder.APP && c.workflowKey == GOVERNANCE_WORKFLOW && c.objectTypeKey == PROPOSAL
            && c.roleKey == WorkOrder.INSPECTOR && c.stage == AVACoreTypes.Stage.Verification,
            "Inspector transition required");
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata) external pure {
        revert("No governance downstream record");
    }
}

/// @notice Local fixture installed after the independent WorkOrder application.
contract InstallRuleLifecycle {
    RuleLifecycleVm private constant vm = RuleLifecycleVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant GOVERNANCE_WORKFLOW = keccak256("independent.work-order.governance.v1");
    bytes32 private constant PUBLISHER = keccak256("independent.work-order.governance.bootstrap.v1");

    function run(address admin, AVAGovernanceKernel kernel, AVAChallengeExtension challenges,
        address requester, address inspector, address manager) external
    {
        require(block.chainid == 31337, "Local chain only");
        require(admin != address(0) && requester != address(0) && inspector != address(0) && manager != address(0)
            && admin != requester && admin != inspector && admin != manager && requester != inspector
            && requester != manager && inspector != manager, "Separate actors required");
        require(address(challenges.GOVERNANCE_KERNEL()) == address(kernel), "Mixed Core");
        AVAIdentityRegistry identities = kernel.IDENTITY_REGISTRY();
        require(identities.APPLICATION_REGISTRY().ADMIN() == admin, "Wrong Core admin");
        require(identities.subjectOf(requester, WorkOrder.APP, WorkOrder.REQUESTER) == _subject(requester, WorkOrder.REQUESTER)
            && identities.subjectOf(inspector, WorkOrder.APP, WorkOrder.INSPECTOR) == _subject(inspector, WorkOrder.INSPECTOR)
            && identities.subjectOf(manager, WorkOrder.APP, WorkOrder.MANAGER) == _subject(manager, WorkOrder.MANAGER),
            "Wrong WorkOrder actors");
        AVACoreRulePackageRegistry registry = kernel.RULE_PACKAGE_REGISTRY();
        uint256 target = registry.getActivePackageId(WorkOrder.APP, WorkOrder.WORKFLOW);
        require(target != 0, "WorkOrder not installed");
        require(kernel.sourceBoundTransitionRequesterByPackage(target) == address(challenges)
            && address(kernel.transitionGuardByPackage(target)) == address(challenges), "Wrong target correction route");

        vm.startBroadcast(admin);
        WorkOrderGovernanceModule application = new WorkOrderGovernanceModule();
        new RetiredWorkOrderModule();
        bytes32[] memory revisers = new bytes32[](1);
        revisers[0] = _subject(manager, WorkOrder.MANAGER);
        AVALocalRuleRevisionPolicy policy = new AVALocalRuleRevisionPolicy(
            identities, WorkOrder.APP, GOVERNANCE_WORKFLOW, 0, true, true, revisers
        );
        bytes32 publisher = _subject(admin, PUBLISHER);
        identities.assignSubject(admin, WorkOrder.APP, PUBLISHER, publisher, "local:rule-governance-bootstrap");
        AVAAuthorityMatrix authority = kernel.AUTHORITY_MATRIX();
        authority.setPermission(WorkOrder.APP, PUBLISHER, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, true);
        uint256 governing = registry.registerRulePackage(
            AVACoreRulePackageRegistry.PackageRegistrationInput(WorkOrder.APP, GOVERNANCE_WORKFLOW, PUBLISHER,
                publisher, 1, keccak256("work-order.governance.compatibility.v1"), "local:work-order/governance"),
            _governingBindings(registry, target, address(application), address(policy))
        );
        kernel.bindSourceBoundTransitionRequester(governing, address(challenges));
        kernel.bindTransitionGuard(governing, address(challenges));
        AVARecognisedRuleGovernance controller = new AVARecognisedRuleGovernance(kernel, GOVERNANCE_WORKFLOW);
        registry.sealGovernance(WorkOrder.APP, GOVERNANCE_WORKFLOW, governing, controller);
        registry.sealGovernance(WorkOrder.APP, WorkOrder.WORKFLOW, target, controller);
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](3);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(WorkOrder.REQUESTER, controller.ACTION_PROPOSE_RULE_REVISION(), true);
        updates[1] = AVAAuthorityMatrix.PermissionUpdate(WorkOrder.MANAGER, controller.ACTION_REVISE_RULE(), true);
        updates[2] = AVAAuthorityMatrix.PermissionUpdate(PUBLISHER, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, false);
        authority.setPermissions(WorkOrder.APP, updates);
        identities.deactivateSubject(publisher);
        vm.stopBroadcast();
    }

    function _subject(address actor, bytes32 role) private pure returns (bytes32) {
        return keccak256(abi.encode(WorkOrder.APP, role, actor));
    }

    function _governingBindings(AVACoreRulePackageRegistry registry, uint256 target, address application, address policy)
        private view returns (AVACoreRulePackageRegistry.ModuleBinding[] memory bindings)
    {
        bytes32[] memory keys = registry.getCapabilityKeys(target);
        bindings = new AVACoreRulePackageRegistry.ModuleBinding[](keys.length + 1);
        for (uint256 i; i < keys.length; ++i) {
            require(keys[i] != AVACapabilityKeys.RULE_REVISION, "Unexpected revision binding");
            address module = keys[i] == AVACapabilityKeys.APPLICATION ? application : registry.getModule(target, keys[i]);
            bindings[i] = AVACoreRulePackageRegistry.ModuleBinding(keys[i], IRuleModuleIdentity(module));
        }
        bindings[keys.length] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.RULE_REVISION,
            IRuleModuleIdentity(policy));
    }
}
