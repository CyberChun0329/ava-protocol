// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {AVARequestSupportDeployment} from "../src/extensions/requests/AVARequestSupportDeployment.sol";
import {AVAExecutionLifecycle} from "../src/extensions/requests/AVAExecutionLifecycle.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVACorrectionDeployment} from "../src/core/AVACorrectionDeployment.sol";
import {AVAGovernedObjectValidation} from "../src/core/AVAGovernedObjectValidation.sol";
import {AVAWorkflowPolicyRouter} from "../src/core/AVAWorkflowPolicyRouter.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";

/// @dev A module is entitled to observe the Kernel as caller and the original actor in context.
contract KernelCallerApplicationFixture is IAVAApplicationModule, RuleModuleIdentity {
    bytes32 private immutable APP;
    address private immutable KERNEL;
    address private immutable ACTOR;

    constructor(bytes32 app, address kernel, address actor) {
        APP = app;
        KERNEL = kernel;
        ACTOR = actor;
    }

    function applicationId() external view returns (bytes32) {
        return APP;
    }

    function validateGovernedObject(GovernedObjectContext calldata context) external view {
        require(msg.sender == KERNEL && context.actor == ACTOR && context.appId == APP, "object caller changed");
    }
    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata) external pure {}
    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata) external pure {}
    function validateEvidence(EvidenceContext calldata) external pure {}
    function validateDownstreamRecord(DownstreamRecordContext calldata) external pure {}

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(APP, KERNEL, ACTOR));
    }
}

contract RequestDeploymentTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("request.deployment.app");

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("request.deployment.object"));
    }

    /// @notice The public deployment payload must leave at least 4 KiB below EIP-3860.
    function testRequestDeploymentLeavesFourKiBOfInitcodeHeadroom() public pure {
        uint256 initcodeBytes = type(AVARequestAllocation).creationCode.length + abi.encode(address(0)).length;
        require(initcodeBytes <= 49_152 - 4_096, "request deployment lacks 4 KiB initcode headroom");
    }

    function testKernelDeploymentLeavesFourKiBOfInitcodeHeadroom() public pure {
        uint256 initcodeBytes = type(AVAGovernanceKernel).creationCode.length + 6 * 32;
        require(initcodeBytes <= 49_152 - 4_096, "kernel deployment lacks 4 KiB initcode headroom");
    }

    function testRequestRuntimeLeavesAtLeast512BytesOfHeadroom() public view {
        require(address(requestAllocation).code.length <= 24_576 - 512, "request runtime lacks 512 bytes headroom");
    }

    function testKernelRuntimeLeavesAtLeastOneKiBOfHeadroom() public view {
        require(address(kernel).code.length <= 24_576 - 1_024, "kernel runtime lacks 1 KiB headroom");
    }

    function testObjectPolicyRetainsKernelCallerAndOriginalActor() public {
        requestPackageId =
            _registerRequestPackage(new KernelCallerApplicationFixture(APP, address(kernel), SOURCE_ACTOR), 2);
        uint256 stateId = _createStateForCommitment(keccak256("caller-sensitive governed object"));
        require(kernel.getRecognisedStateReference(stateId).packageId == requestPackageId);
    }

    function testMissingObjectValidationLibraryRejectsBeforeRecordingAnObject() public {
        uint256 source = _createStateForCommitment(keccak256("retained before library loss"));
        AVACoreTypes.GovernedObjectRecord memory objectRecord =
            kernel.getGovernedObject(kernel.getRecognisedStateReference(source).governedObjectId);
        AVAGovernanceKernel.GovernedObjectInput memory input = AVAGovernanceKernel.GovernedObjectInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            roleKey: ROLE_SOURCE,
            objectTypeKey: requestObjectTypeKey,
            objectCommitment: keccak256("new object after library loss"),
            parentObjectId: 0,
            subjectId: _authority(ROLE_SOURCE),
            evidenceReceiptId: objectRecord.evidenceReceiptId,
            disclosurePolicyId: requestPolicyId,
            metadataHash: keccak256("new metadata"),
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:object"
        });
        uint256 nextId = kernel.nextGovernedObjectId();
        requestVm.etch(address(AVAGovernedObjectValidation), hex"");
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        kernel.registerGovernedObject(input);
        require(kernel.nextGovernedObjectId() == nextId, "missing validator recorded object");
        require(kernel.getRecognisedStateReference(source).status == AVACoreTypes.RecognisedStateStatus.Vested);
    }

    function testCorrectionCreationLibraryBindsRegistryAndHasNoRuntimeRole() public {
        require(address(kernel.CORRECTIONS().GOVERNANCE_KERNEL()) == address(kernel), "wrong review host");
        (bool called,) = address(AVACorrectionDeployment)
            .call(abi.encodeWithSelector(AVACorrectionDeployment.deploy.selector, kernel));
        require(!called, "creation library allowed direct calls");
        requestVm.etch(address(AVACorrectionDeployment), hex"");
        uint256 state = _createStateForCommitment(keccak256("existing kernel remains usable"));
        require(state != 0, "existing kernel depended on creation library");
        AVAWorkflowPolicyRouter router = kernel.POLICY_ROUTER();
        requestVm.expectRevert();
        new AVAGovernanceKernel(
            authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry, disclosureRegistry, router
        );
    }

    function testFreshHelpersBelongToEachAllocationAndExecuteUnderItsAuthority() public {
        AVARequestAllocation other = new AVARequestAllocation(kernel);
        require(address(requestAllocation.SUPPORT()) != address(other.SUPPORT()), "support shared between hosts");
        require(address(requestAllocation.EXECUTION()) != address(other.EXECUTION()), "execution shared between hosts");
        require(requestAllocation.SUPPORT().REQUEST_ALLOCATION() == address(requestAllocation), "wrong support owner");
        require(
            requestAllocation.EXECUTION().REQUEST_ALLOCATION() == address(requestAllocation), "wrong execution owner"
        );
        require(other.SUPPORT().REQUEST_ALLOCATION() == address(other), "wrong second support owner");
        require(other.EXECUTION().REQUEST_ALLOCATION() == address(other), "wrong second execution owner");
        require(address(requestAllocation.SUPPORT().GOVERNANCE_KERNEL()) == address(kernel), "wrong helper kernel");
        require(address(other.SUPPORT().GOVERNANCE_KERNEL()) == address(kernel), "wrong second helper kernel");

        // Existing allocations do not depend on the creation library after construction.
        requestVm.etch(address(AVARequestSupportDeployment), hex"");
        bytes32 response = keccak256("deployment.response");
        bytes32 parameters = keccak256("deployment.parameters");
        bytes32 burden = keccak256("deployment.burden");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 state = _createStateForCommitment(
            requestAllocation.commitmentFor(APP, address(this), response, parameters, burden, expiry)
        );
        requestVm.prank(SOURCE_ACTOR);
        uint256 id = requestAllocation.createRequest(
            AVARequestAllocation.RequestInput(state, address(this), response, parameters, burden, expiry),
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
        requestVm.expectRevert();
        requestAllocation.consume(id, response, parameters, SOURCE_ACTOR);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestAllocation.consume(id, response, parameters, SOURCE_ACTOR);
        requestAllocation.complete(id, keccak256("deployment.effect"));
        require(requestAllocation.getRequest(id).completed, "bound helpers did not execute approved request");
        require(other.nextRequestId() == 1, "first host changed second host state");
    }

    function testOtherHostAndExternalActorCannotMutateBoundHelpers() public {
        AVARequestAllocation other = new AVARequestAllocation(kernel);
        AVARequestSupport support = requestAllocation.SUPPORT();
        AVAExecutionLifecycle execution = requestAllocation.EXECUTION();
        IAVARequestPolicy.RequestContext memory context;
        context.requestAllocation = address(requestAllocation);
        context.requestId = 777;
        context.exactCommitment = true;
        IAVARequestPolicy.WitnessInput[] memory witnesses = new IAVARequestPolicy.WitnessInput[](0);
        requestVm.prank(address(other));
        (bool bound, bytes memory reason) = address(support).call(abi.encodeCall(support.bind, (context, 1, witnesses)));
        require(!bound && _invalid(reason, 777), "other allocation bound this host's support");
        requestVm.prank(SOURCE_ACTOR);
        (bound, reason) = address(support).call(abi.encodeCall(support.bind, (context, 1, witnesses)));
        require(!bound && _invalid(reason, 777), "external actor bound support");
        requestVm.prank(address(other));
        (bool declared, bytes memory executionReason) = address(execution)
            .call(abi.encodeCall(execution.declareSplit, (1, address(this), bytes32(uint256(1)), bytes32(uint256(2)))));
        require(!declared && _invalid(executionReason, 0), "other allocation controlled this host's execution");
        require(!execution.isSplit(1), "rejected cross-host call changed execution");
        requestVm.expectRevert();
        support.requestContext(777);
    }

    function testLinkedCreationLibraryRejectsDirectCalls() public {
        AVARequestSupport support = requestAllocation.SUPPORT();
        bytes memory callData = abi.encodeWithSelector(
            AVARequestSupportDeployment.deploy.selector,
            kernel,
            address(requestAllocation.EXECUTION()),
            AVARequestSupport.HostComponents(
                authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry, kernel.POLICY_ROUTER()
            )
        );
        (bool created,) = address(AVARequestSupportDeployment).call(callData);
        require(!created, "creation library accepted a direct call");
        require(address(requestAllocation.SUPPORT()) == address(support), "bound support replaced");
        require(support.REQUEST_ALLOCATION() == address(requestAllocation), "immutable helper owner changed");
    }

    function testMissingCreationLibraryCannotLeaveAnInitialisedAllocation() public {
        requestVm.etch(address(AVARequestSupportDeployment), hex"");
        requestVm.expectRevert();
        new AVARequestAllocation(kernel);
    }

    function _invalid(bytes memory reason, uint256 id) private pure returns (bool) {
        return keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
    }
}
