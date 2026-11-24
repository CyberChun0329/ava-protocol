// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {WorkOrder, WorkOrderModule, WorkOrderLedger} from "../src/WorkOrder.sol";
import {AVACoreTypes} from "@ava-protocol/contracts/src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "@ava-protocol/contracts/src/core/AVAGovernanceKernel.sol";
import {
    AVARequestAllocation,
    AVARequestCorrectionActions
} from "@ava-protocol/contracts/src/extensions/requests/AVARequestAllocation.sol";
import {AVAChallengeExtension} from "@ava-protocol/contracts/src/extensions/challenge/AVAChallengeExtension.sol";
import {AVAApplicationRegistry} from "@ava-protocol/contracts/src/AVAApplicationRegistry.sol";
import {AVAIdentityRegistry} from "@ava-protocol/contracts/src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "@ava-protocol/contracts/src/core/AVAAuthorityMatrix.sol";
import {AVACoreRulePackageRegistry} from "@ava-protocol/contracts/src/core/AVACoreRulePackageRegistry.sol";
import {DefaultAVACorePolicyBundle} from "@ava-protocol/contracts/src/core/modules/DefaultAVACoreRuleModules.sol";
import {
    DefaultAVAExtensionPolicyModule
} from "@ava-protocol/contracts/src/extensions/shared/DefaultAVAExtensionPolicyModule.sol";
import {AVABoundRequestPolicy} from "@ava-protocol/contracts/src/extensions/requests/AVABoundRequestPolicy.sol";
import {AVADefaultBindings} from "@ava-protocol/contracts/script/AVADefaultBindings.sol";
import {AVADefaultPolicies} from "@ava-protocol/contracts/script/AVADefaultPolicies.sol";

interface WorkOrderVm {
    function startBroadcast(address) external;
    function stopBroadcast() external;
}

/// @notice Consumer-owned installer: the installed package provides only generic Core and policies.
contract InstallWorkOrder {
    WorkOrderVm private constant vm = WorkOrderVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant PUBLISHER = keccak256("independent.work-order.bootstrap.v1");

    struct Installation {
        AVAGovernanceKernel kernel;
        AVARequestAllocation requests;
        AVAChallengeExtension challenges;
        address admin;
        address requester;
        address inspector;
        address manager;
    }

    function run(
        address admin,
        AVAGovernanceKernel kernel,
        AVARequestAllocation requests,
        AVAChallengeExtension challenges,
        address requester,
        address inspector,
        address manager
    ) external {
        _run(Installation(kernel, requests, challenges, admin, requester, inspector, manager),
            DefaultAVACorePolicyBundle(address(0)), DefaultAVAExtensionPolicyModule(address(0)));
    }

    /// @notice Reuse only the exact stateless defaults; application-bound policies are installed afresh.
    function runWithPolicies(
        address admin,
        AVAGovernanceKernel kernel,
        AVARequestAllocation requests,
        AVAChallengeExtension challenges,
        address requester,
        address inspector,
        address manager,
        DefaultAVACorePolicyBundle corePolicy,
        DefaultAVAExtensionPolicyModule extensionPolicy
    ) external {
        AVADefaultPolicies.requireExact(corePolicy, extensionPolicy);
        _run(Installation(kernel, requests, challenges, admin, requester, inspector, manager), corePolicy, extensionPolicy);
    }

    function _run(
        Installation memory d, DefaultAVACorePolicyBundle corePolicy, DefaultAVAExtensionPolicyModule extensionPolicy
    ) private {
        require(block.chainid == 31337, "Local chain only");
        require(
            d.admin != address(0) && d.requester != address(0) && d.inspector != address(0) && d.manager != address(0)
                && d.requester != d.inspector && d.requester != d.manager && d.inspector != d.manager
                && d.admin != d.requester && d.admin != d.inspector && d.admin != d.manager,
            "Separate actors required"
        );
        require(
            address(d.requests.GOVERNANCE_KERNEL()) == address(d.kernel)
                && address(d.challenges.GOVERNANCE_KERNEL()) == address(d.kernel),
            "Mixed Core"
        );
        _install(d, corePolicy, extensionPolicy);
    }

    function _install(
        Installation memory d, DefaultAVACorePolicyBundle corePolicy, DefaultAVAExtensionPolicyModule extensionPolicy
    ) private {
        AVAIdentityRegistry identities = d.kernel.IDENTITY_REGISTRY();
        AVAApplicationRegistry applications = identities.APPLICATION_REGISTRY();
        AVAAuthorityMatrix authority = d.kernel.AUTHORITY_MATRIX();
        require(applications.ADMIN() == d.admin, "Wrong Core admin");
        vm.startBroadcast(d.admin);
        WorkOrderModule module = new WorkOrderModule();
        WorkOrderLedger ledger = new WorkOrderLedger(d.requests);
        if (address(corePolicy) == address(0)) corePolicy = new DefaultAVACorePolicyBundle();
        if (address(extensionPolicy) == address(0)) extensionPolicy = new DefaultAVAExtensionPolicyModule();
        AVABoundRequestPolicy allocation = new AVABoundRequestPolicy(
            address(d.requests), WorkOrder.APP, WorkOrder.WORKFLOW, address(ledger), WorkOrder.CLOSE, WorkOrder.BURDEN
        );
        applications.registerApplication(
            WorkOrder.APP,
            keccak256("work-order.schema.v1"),
            keccak256("work-order.authority.v1"),
            d.admin,
            "local:independent-work-order"
        );
        d.kernel.CORRECTIONS().bindRequestOrigin(WorkOrder.APP, address(d.requests));
        bytes32 publisher = subject(d.admin, PUBLISHER);
        identities.assignSubject(d.admin, WorkOrder.APP, PUBLISHER, publisher, "local:bootstrap");
        _publisherPermissions(authority, true);
        uint256 packageId = d.kernel.RULE_PACKAGE_REGISTRY()
            .registerRulePackage(
                AVACoreRulePackageRegistry.PackageRegistrationInput(
                    WorkOrder.APP,
                    WorkOrder.WORKFLOW,
                    PUBLISHER,
                    publisher,
                    1,
                    keccak256("work-order.compatibility.v1"),
                    "local:work-order/rules"
                ),
                AVADefaultBindings.bindings(
                    address(module), address(corePolicy), address(extensionPolicy), address(allocation)
                )
            );
        d.kernel.DISCLOSURE_REGISTRY()
            .registerPolicy(
                WorkOrder.APP,
                PUBLISHER,
                publisher,
                keccak256("work-order.public-commitments.v1"),
                "Synthetic public inspections",
                "local:disclosure"
            );
        d.kernel.bindSourceBoundTransitionRequester(packageId, address(d.challenges));
        d.kernel.bindTransitionGuard(packageId, address(d.challenges));
        _publisherPermissions(authority, false);
        identities.deactivateSubject(publisher);
        identities.assignSubject(
            d.requester,
            WorkOrder.APP,
            WorkOrder.REQUESTER,
            subject(d.requester, WorkOrder.REQUESTER),
            "local:requester"
        );
        identities.assignSubject(
            d.inspector,
            WorkOrder.APP,
            WorkOrder.INSPECTOR,
            subject(d.inspector, WorkOrder.INSPECTOR),
            "local:inspector"
        );
        identities.assignSubject(
            d.manager, WorkOrder.APP, WorkOrder.MANAGER, subject(d.manager, WorkOrder.MANAGER), "local:manager"
        );
        AVAAuthorityMatrix.PermissionUpdate[] memory permissions = new AVAAuthorityMatrix.PermissionUpdate[](10);
        permissions[0] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.REQUESTER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        permissions[1] = AVAAuthorityMatrix.PermissionUpdate(
            WorkOrder.REQUESTER, d.kernel.EVIDENCE_REGISTRY().ACTION_REGISTER_CORRECTION_EVIDENCE(), true
        );
        permissions[2] = AVAAuthorityMatrix.PermissionUpdate(
            WorkOrder.REQUESTER, AVACoreTypes.ACTION_REGISTER_GOVERNED_OBJECT, true
        );
        permissions[3] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.REQUESTER, d.requests.ACTION_CREATE_REQUEST(), true);
        permissions[4] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.REQUESTER, AVARequestCorrectionActions.FILE, true);
        permissions[5] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.INSPECTOR, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        permissions[6] = AVAAuthorityMatrix.PermissionUpdate(
            WorkOrder.INSPECTOR, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE, true
        );
        permissions[7] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.INSPECTOR, AVACoreTypes.ACTION_VEST_RECOGNISED_STATE, true);
        permissions[8] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.MANAGER, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        permissions[9] =
            AVAAuthorityMatrix.PermissionUpdate(WorkOrder.INSPECTOR, AVARequestCorrectionActions.RESOLVE, true);
        authority.setPermissions(WorkOrder.APP, permissions);
        vm.stopBroadcast();
    }

    function subject(address actor, bytes32 role) private pure returns (bytes32) {
        return keccak256(abi.encode(WorkOrder.APP, role, actor));
    }

    function _publisherPermissions(AVAAuthorityMatrix authority, bool allowed) private {
        AVAAuthorityMatrix.PermissionUpdate[] memory updates = new AVAAuthorityMatrix.PermissionUpdate[](2);
        updates[0] = AVAAuthorityMatrix.PermissionUpdate(PUBLISHER, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, allowed);
        updates[1] =
            AVAAuthorityMatrix.PermissionUpdate(PUBLISHER, AVACoreTypes.ACTION_REGISTER_DISCLOSURE_POLICY, allowed);
        authority.setPermissions(WorkOrder.APP, updates);
    }
}
