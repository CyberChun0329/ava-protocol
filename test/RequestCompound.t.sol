// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {RequestExecutor, RequestTestApplicationModule} from "./RequestAllocation.t.sol";
import {RequestCorrectionApplication} from "./RequestCorrections.t.sol";

import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {IAVAAllocationPolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";

/// @notice A custom policy can independently reject support, core Allocation, or its final decision.
contract CompoundRequestPolicy is IAVARequestPolicy, IAVAAllocationPolicyModule, RuleModuleIdentity {
    error SupportRejected();
    error AllocationRejected();
    error DecisionRejected();
    bool private rejectSupport;
    bool private rejectAllocation;
    bool private rejectDecision;

    function setRejections(bool support, bool allocation, bool decision) external {
        rejectSupport = support;
        rejectAllocation = allocation;
        rejectDecision = decision;
    }

    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external view {
        if (rejectSupport) revert SupportRejected();
        AVARequestAllocation owner = AVARequestAllocation(request.requestAllocation);
        require(owner.supportWitnessHash(request.requestId) != bytes32(0), "support not bound");
        require(witness.length == 1 && witness[0].recognisedStateId == request.primaryRecognisedStateId, "wrong witness");
        require(owner.requestIdByRecognisedState(request.primaryRecognisedStateId) == request.requestId, "wrong source");
    }

    function validateAllocation(AllocationPolicyContext calldata) external view {
        if (rejectAllocation) revert AllocationRejected();
    }

    function validateRequestAllocation(RequestContext calldata request, Witness[] calldata, DecisionContext calldata decision)
        external view
    {
        if (rejectDecision) revert DecisionRejected();
        address allocator = AVARequestAllocation(request.requestAllocation).getRequest(request.requestId).allocator;
        require(allocator == address(0) || allocator == decision.actor, "wrong recorded allocator");
    }
}

interface RequestCompoundVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }
    function snapshotState() external returns (uint256);
    function revertToState(uint256 id) external returns (bool);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

contract RequestCompoundTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("request.compound.app");
    bytes32 private constant RESPONSE = keccak256("request.compound.response");
    bytes32 private constant PARAMETERS = keccak256("request.compound.parameters");
    bytes32 private constant BURDEN = keccak256("request.compound.burden");
    bytes32 private constant OBJECT = keccak256("request.compound.object");
    bytes32 private constant CREATOR_AUTHORITY = keccak256("request.compound.creator");
    RequestExecutor private executor;
    RequestCompoundVm private constant compoundVm =
        RequestCompoundVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string key, uint256 value);

    function setUp() public {
        _setUpRequestAllocation(APP, new RequestTestApplicationModule(APP, OBJECT, RESPONSE), OBJECT);
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_SOURCE, CREATOR_AUTHORITY, "test:creator");
        executor = new RequestExecutor();
    }

    function testOneSignerCreatesAndApprovesWithBothExplicitAuthorities() public {
        AVARequestAllocation.RequestInput memory input = _input();
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 id = requestAllocation.createAndApproveRequest(
            input, ROLE_SOURCE, CREATOR_AUTHORITY, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
        );
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.creator == ALLOCATOR_ACTOR && record.allocator == ALLOCATOR_ACTOR, "actor not preserved");
        require(record.creatorRoleKey == ROLE_SOURCE && record.creatorAuthorityId == CREATOR_AUTHORITY, "creation");
        require(
            record.allocatorRoleKey == ROLE_ALLOCATOR && record.allocatorAuthorityId == _authority(ROLE_ALLOCATOR),
            "allocation"
        );
        require(requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)), "not executable");
        require(!record.consumed && !record.completed, "approval executed effect");
    }

    function testSeparateAndCompoundCallsRetainIdenticalRecordsWitnessesAndEvents() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 snapshot = compoundVm.snapshotState();
        compoundVm.recordLogs();
        requestVm.startPrank(ALLOCATOR_ACTOR);
        uint256 separateId = requestAllocation.createRequest(input, ROLE_SOURCE, CREATOR_AUTHORITY);
        requestAllocation.approve(separateId, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestVm.stopPrank();
        RequestCompoundVm.Log[] memory separateLogs = compoundVm.getRecordedLogs();
        bytes32 separateRecord = keccak256(abi.encode(requestAllocation.getRequest(separateId)));
        bytes32 separateWitness = keccak256(abi.encode(requestAllocation.getSupportWitness(separateId)));
        require(compoundVm.revertToState(snapshot), "restore failed");
        compoundVm.recordLogs();
        uint256 compoundId = _combined(input);
        RequestCompoundVm.Log[] memory compoundLogs = compoundVm.getRecordedLogs();
        require(compoundId == separateId, "request identity changed");
        require(keccak256(abi.encode(requestAllocation.getRequest(compoundId))) == separateRecord, "record differs");
        require(
            keccak256(abi.encode(requestAllocation.getSupportWitness(compoundId))) == separateWitness, "witness differs"
        );
        require(keccak256(abi.encode(compoundLogs)) == keccak256(abi.encode(separateLogs)), "events differ");
    }

    function testMissingCreationPermissionRejectsWithoutReservingThenLegalFlowWorks() public {
        AVARequestAllocation.RequestInput memory input = _input();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_CREATE_REQUEST(), false);
        requestVm.expectRevert();
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_CREATE_REQUEST(), true);
        require(_combined(input) == 1, "failed creation reserved identity");
    }

    function testMissingAllocationPermissionRollsBackRequestAndSupportThenLegalFlowWorks() public {
        AVARequestAllocation.RequestInput memory input = _input();
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        require(_combined(input) == 1, "failed Allocation reserved identity");
        executor.execute(requestAllocation, 1, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(1).completed, "rollback blocked legal effect");
    }

    function testCreationAuthorityCannotStandInForAllocationAuthority() public {
        AVARequestAllocation.RequestInput memory input = _input();
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createAndApproveRequest(input, ROLE_SOURCE, CREATOR_AUTHORITY, ROLE_SOURCE, CREATOR_AUTHORITY);
        _assertNoRequest(input.recognisedStateId);
        require(_combined(input) == 1, "wrong authority reserved request");
    }

    function testCanonicalRolesDoNotBypassApplicationActorPolicy() public {
        AVARequestAllocation.RequestInput memory input = _input();
        address wrongActor = address(0xBAD);
        bytes32 creator = keccak256("wrong.actor.creator");
        bytes32 allocator = keccak256("wrong.actor.allocator");
        identityRegistry.assignSubject(wrongActor, APP, ROLE_SOURCE, creator, "test:wrong-creator");
        identityRegistry.assignSubject(wrongActor, APP, ROLE_ALLOCATOR, allocator, "test:wrong-allocator");
        requestVm.prank(wrongActor);
        requestVm.expectRevert();
        requestAllocation.createAndApproveRequest(input, ROLE_SOURCE, creator, ROLE_ALLOCATOR, allocator);
        _assertNoRequest(input.recognisedStateId);
        require(_combined(input) == 1, "domain rejection reserved request");
    }

    function testWrongParametersAndWrongSourceCannotReplaceExactSupport() public {
        AVARequestAllocation.RequestInput memory input = _input();
        bytes32 originalParameters = input.parametersHash;
        input.parametersHash = keccak256("wrong parameters");
        requestVm.expectRevert();
        _combined(input);
        input.parametersHash = originalParameters;
        uint256 rightSource = input.recognisedStateId;
        input.recognisedStateId = _createStateForCommitment(keccak256("another case"));
        requestVm.expectRevert();
        _combined(input);
        _assertNoRequest(rightSource);
        _assertNoRequest(input.recognisedStateId);
        input.recognisedStateId = rightSource;
        require(_combined(input) == 1, "bad support reserved request");
    }

    function testExpiredRequestIsRejectedBeforeCreation() public {
        AVARequestAllocation.RequestInput memory input = _input();
        requestVm.warp(input.validUntil);
        requestVm.expectRevert();
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        require(_combined(_input()) == 1, "expiry reserved request");
    }

    function testExecutionStillRechecksEvidenceAndRollsBackFailedExternalEffect() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 id = _combined(input);
        bytes32 beforeEffect = keccak256(abi.encode(requestAllocation.getRequest(id)));
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, true);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(id))) == beforeEffect, "failed effect changed history"
        );
        uint256 snapshot = compoundVm.snapshotState();
        uint256 evidenceId = requestAllocation.getRequest(id).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidenceId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("revoke"),
            "test:revoke"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(id))) == beforeEffect, "revoked effect changed history"
        );
        require(compoundVm.revertToState(snapshot), "restore failed");
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(id);
        require(completed.consumed && completed.completed, "legal effect incomplete");
        require(completed.creator == ALLOCATOR_ACTOR && completed.allocator == ALLOCATOR_ACTOR, "actor history");
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        require(keccak256(abi.encode(requestAllocation.getRequest(id))) == keccak256(abi.encode(completed)), "replay");
    }

    function testIndependentWithdrawalKeepsOriginalHistoryAndCombinedSuccessorNeedsFreshAllocation() public {
        requestPackageId = _registerRequestPackage(new RequestCorrectionApplication(APP, RESPONSE), 2);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_RESOLVE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 id = _combined(input);
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        requestVm.prank(SOURCE_ACTOR);
        uint256 challengeId = requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            original.evidenceReceiptId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            keccak256("bounded Allocation challenge")
        );
        requestVm.prank(VERIFIER_ACTOR);
        uint256 decisionEvidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_VERIFIER,
                subjectId: _authority(ROLE_VERIFIER),
                commitment: keccak256("independent decision evidence"),
                evidenceTypeHash: keccak256("correction.decision"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_VERIFIER),
                uri: "test:decision"
            })
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(
            AVARequestAllocation.ResolutionInput({
                challengeId: challengeId,
                expectedPreviousResolutionId: 0,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                decisionEvidenceId: decisionEvidenceId,
                outcome: AVARequestAllocation.ResolutionOutcome.Withdrawn,
                reasonHash: keccak256("independent withdrawal"),
                remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
                finding: _findingInput(true)
            })
        );
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == challengeId, "withdrawal missing");
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        uint256 successor = _combined(input);
        require(requestAllocation.getRequest(successor).supersedesRequestId == id, "predecessor missing");
        require(requestAllocation.getRequest(successor).allocator == ALLOCATOR_ACTOR, "fresh allocation missing");
        executor.execute(requestAllocation, successor, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(successor).completed, "corrective successor incomplete");
        require(keccak256(abi.encode(requestAllocation.getRequest(id))) == keccak256(abi.encode(original)), "history");
        require(
            kernel.getRecognisedStateReference(input.recognisedStateId).lastTransitionId
                == original.recognisedStateTransitionId,
            "Allocation correction changed recognition"
        );
    }

    /// @notice Public call diagnostics share warmed fixture access; transaction intrinsic gas is excluded.
    function testSeparatePublicCallCost() public {
        AVARequestAllocation.RequestInput memory input = _input();
        bytes memory creation = abi.encodeCall(requestAllocation.createRequest, (input, ROLE_SOURCE, CREATOR_AUTHORITY));
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        (bool created, bytes memory result) = address(requestAllocation).call(creation);
        uint256 creationGas = beforeGas - gasleft();
        require(created, "create failed");
        uint256 id = abi.decode(result, (uint256));
        bytes memory approval =
            abi.encodeCall(requestAllocation.approve, (id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)));
        requestVm.prank(ALLOCATOR_ACTOR);
        beforeGas = gasleft();
        (bool approved,) = address(requestAllocation).call(approval);
        uint256 approvalGas = beforeGas - gasleft();
        require(approved, "approve failed");
        emit log_named_uint("separate create+approve warmed public call gas (no intrinsic)", creationGas + approvalGas);
        emit log_named_uint("separate calldata bytes", creation.length + approval.length);
        require(requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)), "not executable");
    }

    /// @notice Same real fixture and inputs as the separate public-call diagnostic.
    function testCompoundPublicCallCost() public {
        AVARequestAllocation.RequestInput memory input = _input();
        bytes memory creation = abi.encodeCall(
            requestAllocation.createAndApproveRequest,
            (input, ROLE_SOURCE, CREATOR_AUTHORITY, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR))
        );
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        (bool created, bytes memory result) = address(requestAllocation).call(creation);
        uint256 creationGas = beforeGas - gasleft();
        require(created, "compound failed");
        uint256 id = abi.decode(result, (uint256));
        emit log_named_uint("compound warmed public call gas (no intrinsic)", creationGas);
        emit log_named_uint("compound calldata bytes", creation.length);
        require(requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)), "not executable");
    }

    function testCustomSupportAndAllocationRejectionsRollBackThenLegalEffectCompletes() public {
        CompoundRequestPolicy policy = _customPolicy();
        AVARequestAllocation.RequestInput memory input = _input();
        policy.setRejections(true, true, true);
        requestVm.expectRevert(CompoundRequestPolicy.SupportRejected.selector);
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        policy.setRejections(false, true, true);
        requestVm.expectRevert(CompoundRequestPolicy.AllocationRejected.selector);
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        policy.setRejections(false, false, true);
        requestVm.expectRevert(CompoundRequestPolicy.DecisionRejected.selector);
        _combined(input);
        _assertNoRequest(input.recognisedStateId);
        policy.setRejections(false, false, false);
        uint256 id = _combined(input);
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(id).completed, "custom policy blocked legal effect");
    }

    function testOrdinaryCreationStillRejectsUnsupportedRequestThenRetainsSeparateAllocation() public {
        CompoundRequestPolicy policy = _customPolicy();
        AVARequestAllocation.RequestInput memory input = _input();
        policy.setRejections(true, false, false);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert(CompoundRequestPolicy.SupportRejected.selector);
        requestAllocation.createRequest(input, ROLE_SOURCE, CREATOR_AUTHORITY);
        _assertNoRequest(input.recognisedStateId);
        policy.setRejections(false, false, false);
        requestVm.startPrank(ALLOCATOR_ACTOR);
        uint256 id = requestAllocation.createRequest(input, ROLE_SOURCE, CREATOR_AUTHORITY);
        require(id == 1 && requestAllocation.getRequest(id).allocator == address(0), "creation allocated");
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestVm.stopPrank();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(id).completed, "separate legal effect incomplete");
    }

    function _customPolicy() private returns (CompoundRequestPolicy policy) {
        policy = new CompoundRequestPolicy();
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _coreBindings(new RequestTestApplicationModule(APP, OBJECT, RESPONSE));
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(policy));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(APP, REQUEST_WORKFLOW, ROLE_PACKAGE, _authority(ROLE_PACKAGE), 2,
                keccak256("request.compatibility"), "test:custom-request"), requestPackageId, bindings
        );
    }

    /// @notice Compare public entry points from the same state; no transaction intrinsic gas.
    function testCombinedDecisionSavesSupportValidationGas() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 snapshot = compoundVm.snapshotState();
        requestVm.startPrank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        uint256 id = requestAllocation.createRequest(input, ROLE_SOURCE, CREATOR_AUTHORITY);
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        uint256 separateGas = beforeGas - gasleft();
        requestVm.stopPrank();
        require(compoundVm.revertToState(snapshot), "restore failed");
        requestVm.prank(ALLOCATOR_ACTOR);
        beforeGas = gasleft();
        requestAllocation.createAndApproveRequest(
            input, ROLE_SOURCE, CREATOR_AUTHORITY, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
        );
        uint256 combinedGas = beforeGas - gasleft();
        emit log_named_uint("separate warmed public call gas", separateGas);
        emit log_named_uint("combined warmed public call gas", combinedGas);
        require(combinedGas + 20_000 < separateGas, "combined request repeats support work");
    }

    function _combined(AVARequestAllocation.RequestInput memory input) private returns (uint256) {
        requestVm.prank(ALLOCATOR_ACTOR);
        return requestAllocation.createAndApproveRequest(
            input, ROLE_SOURCE, CREATOR_AUTHORITY, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
        );
    }

    function _assertNoRequest(uint256 sourceId) private {
        require(requestAllocation.nextRequestId() == 1, "request counter reserved");
        require(requestAllocation.requestIdByRecognisedState(sourceId) == 0, "source reserved");
        require(requestAllocation.supportWitnessHash(1) == bytes32(0), "support hash retained");
        requestVm.expectRevert();
        requestAllocation.getRequest(1);
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.expectRevert();
        support.requestContext(1);
    }

    function _input() private returns (AVARequestAllocation.RequestInput memory input) {
        uint64 validUntil = uint64(block.timestamp + 1 days);
        input = AVARequestAllocation.RequestInput({
            recognisedStateId: _createRequestState(address(executor), RESPONSE, PARAMETERS, BURDEN, validUntil),
            executor: address(executor),
            responseClass: RESPONSE,
            parametersHash: PARAMETERS,
            burdenHash: BURDEN,
            validUntil: validUntil
        });
    }
}
