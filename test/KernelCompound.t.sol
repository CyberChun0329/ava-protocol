// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVATransitionGuard} from "../src/core/interfaces/IAVATransitionGuard.sol";
import {IAVAPostTransitionHook} from "../src/core/interfaces/IAVAPostTransitionHook.sol";
import {AVAAuthorityMatrix} from "../src/core/AVAAuthorityMatrix.sol";
import {AVAApplicationRegistry} from "../src/AVAApplicationRegistry.sol";

interface CompoundVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function snapshotState() external returns (uint256);
    function revertToState(uint256) external returns (bool);
}

contract CompoundTimeGuard is IAVATransitionGuard {
    uint256 private immutable earliest;

    constructor(uint256 earliest_) {
        earliest = earliest_;
    }

    function moduleIdentityHash() external view returns (bytes32) {
        return keccak256(abi.encode(address(this).codehash));
    }

    function validateTransition(
        uint256,
        uint256,
        AVACoreTypes.RecognisedStateStatus,
        AVACoreTypes.RecognisedStateStatus,
        AVACoreTypes.TransitionKind
    ) external view {
        require(block.timestamp >= earliest, "wait before transition");
    }
}

contract CompoundHistoryHook is IAVAPostTransitionHook {
    address private immutable kernel;
    TransitionContext[] private observed;

    constructor(address kernel_) {
        kernel = kernel_;
    }

    function moduleIdentityHash() external view returns (bytes32) {
        return keccak256(abi.encode(address(this).codehash));
    }

    function onRecognisedStateTransition(TransitionContext calldata context) external {
        require(msg.sender == kernel, "only Kernel");
        AVAGovernanceKernel host = AVAGovernanceKernel(kernel);
        AVACoreTypes.RecognisedStateTransitionRecord memory record =
            host.getRecognisedStateTransition(context.transitionId);
        require(
            record.id == context.transitionId && record.recognisedStateId == context.recognisedStateId
                && record.governedObjectId == context.governedObjectId && record.appId == context.appId
                && record.packageId == context.packageId && record.fromStatus == context.fromStatus
                && record.toStatus == context.toStatus && record.kind == context.kind,
            "hook observed incomplete transition"
        );
        require(
            host.getRecognisedStateReference(context.recognisedStateId).lastTransitionId == context.transitionId,
            "hook observed stale parent"
        );
        observed.push(context);
    }

    function count() external view returns (uint256) {
        return observed.length;
    }

    function get(uint256 index) external view returns (TransitionContext memory) {
        return observed[index];
    }
}

contract CompoundRevocationHook is IAVAPostTransitionHook {
    AVAAuthorityMatrix private immutable authority;
    bytes32 private immutable app;
    bytes32 private immutable role;

    constructor(AVAAuthorityMatrix authority_, bytes32 app_, bytes32 role_) {
        authority = authority_;
        app = app_;
        role = role_;
    }

    function moduleIdentityHash() external view returns (bytes32) {
        return keccak256(abi.encode(address(this).codehash));
    }

    function acceptAdmin() external {
        authority.APPLICATION_REGISTRY().acceptApplicationAdmin(app);
    }

    function onRecognisedStateTransition(TransitionContext calldata context) external {
        if (context.kind == AVACoreTypes.TransitionKind.InitialFormation) {
            authority.setPermission(app, role, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE, false);
        }
    }
}

contract CompoundReentryHook is IAVAPostTransitionHook {
    AVAGovernanceKernel private immutable kernel;
    bool public veto;
    uint256 public refusals;
    error HookVeto();

    constructor(AVAGovernanceKernel kernel_) {
        kernel = kernel_;
    }

    function setVeto(bool value) external {
        veto = value;
    }

    function moduleIdentityHash() external view returns (bytes32) {
        return keccak256(abi.encode(address(kernel), address(this).codehash));
    }

    function onRecognisedStateTransition(TransitionContext calldata context) external {
        require(msg.sender == address(kernel), "only Kernel");
        (bool allowed, bytes memory reason) = address(kernel)
            .call(
                abi.encodeCall(
                    kernel.transitionRecognisedState,
                    (AVAGovernanceKernel.RecognisedStateTransitionInput(
                            context.recognisedStateId,
                            bytes32(uint256(1)),
                            bytes32(uint256(2)),
                            AVACoreTypes.RecognisedStateStatus.Challengeable,
                            bytes32(uint256(3)),
                            "test:nested"
                        ))
                )
            );
        require(
            !allowed && keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, 0)),
            "nested transition was not fenced"
        );
        if (veto) revert HookVeto();
        ++refusals;
    }
}

contract KernelCompoundTest is RequestAllocationFixture {
    CompoundVm private constant vm = CompoundVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string key, uint256 value);

    function setUp() public {
        requestVm.warp(1_000_000);
        bytes32 app = keccak256("compound recognition test");
        _setUpRequestAllocation(app, new M14PermissiveApplicationModule(app), keccak256("compound object"));
    }

    function testHistoricalTransitionRetainsActorAfterAuthorityRotation() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, keccak256("challengeable reason"), "test:challengeable");
        uint256 last = kernel.getRecognisedStateReference(id).lastTransitionId;
        AVACoreTypes.RecognisedStateTransitionRecord memory first = kernel.getRecognisedStateTransition(last - 1);
        bytes32 firstHash = keccak256(abi.encode(first));
        bytes32 secondHash = keccak256(abi.encode(kernel.getRecognisedStateTransition(last)));
        bytes32 referenceHash = keccak256(abi.encode(kernel.getRecognisedStateTransitionReference(last)));
        require(
            first.id == last - 1 && first.recognisedStateId == id && first.governedObjectId == input.governedObjectId
                && first.appId == requestAppId && first.workflowKey == REQUEST_WORKFLOW
                && first.packageId == requestPackageId && first.decisionPackageId == requestPackageId
                && first.sourceRecordId == 0 && first.evidenceReceiptId == first.decisionEvidenceReceiptId
                && first.authorityId == _authority(ROLE_VERIFIER) && first.createdBy == VERIFIER_ACTOR
                && first.createdAt == 1_000_000 && first.kind == AVACoreTypes.TransitionKind.InitialFormation
                && first.toStatus == AVACoreTypes.RecognisedStateStatus.Provisional
                && first.reasonHash == input.reasonHash && keccak256(bytes(first.reasonURI)) == keccak256("test:formation"),
            "formation history differs"
        );
        identityRegistry.deactivateSubject(_authority(ROLE_VERIFIER));
        bytes32 replacement = keccak256("replacement verifier");
        identityRegistry.assignSubject(VERIFIER_ACTOR, requestAppId, ROLE_VERIFIER, replacement, "test:replacement");
        AVAGovernanceKernel.RecognisedStateTransitionInput memory next =
            _transitionInput(id, AVACoreTypes.RecognisedStateStatus.Vested);
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(next);
        next.authorityId = replacement;
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(next);
        require(kernel.getRecognisedState(id).authorityId == replacement, "current authority not updated");
        require(keccak256(abi.encode(kernel.getRecognisedStateTransition(last - 1))) == firstHash, "formation rewritten");
        require(keccak256(abi.encode(kernel.getRecognisedStateTransition(last))) == secondHash, "ordinary history rewritten");
        require(keccak256(abi.encode(kernel.getRecognisedStateTransitionReference(last))) == referenceHash, "reference rewritten");
        (bool ok, bytes memory reason) = address(kernel).staticcall(abi.encodeCall(kernel.getRecognisedStateTransition, (9999)));
        require(!ok && keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, 9999)), "unknown full transition");
        (ok, reason) = address(kernel).staticcall(abi.encodeCall(kernel.getRecognisedStateTransitionReference, (9999)));
        require(!ok && keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, 9999)), "unknown reference transition");
    }

    function testTransitionStorageFormationCost() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 beforeGas = gasleft();
        uint256 id = kernel.formChallengeableState(input, keccak256("challengeable reason"), "test:challengeable");
        uint256 cost = beforeGas - gasleft();
        emit log_named_uint("transition storage formation gas", cost);
        require(kernel.getRecognisedStateReference(id).status == AVACoreTypes.RecognisedStateStatus.Challengeable);
        require(cost <= 900_000, "transition storage cost target");
    }

    function testCommitmentReferenceKeepsContextAndFullHistoricalRecord() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        uint256 objectId = input.governedObjectId;
        bytes32 original = keccak256(abi.encode(kernel.getGovernedObject(objectId)));
        uint256 nextState = kernel.nextRecognisedStateId();
        (bool success, bytes memory result) = address(kernel)
            .staticcall(abi.encodeWithSignature("getGovernedObjectCommitmentReference(uint256)", objectId));
        require(success, "commitment reference unavailable");
        require(result.length == 11 * 32, "reference contains variable audit payload");
        (AVAGovernanceKernel.GovernedObjectReference memory context, bytes32 commitment, bytes32 metadata) =
            abi.decode(result, (AVAGovernanceKernel.GovernedObjectReference, bytes32, bytes32));
        require(
            keccak256(abi.encode(context)) == keccak256(abi.encode(kernel.getGovernedObjectReference(objectId))),
            "reference context changed"
        );
        require(commitment == keccak256(abi.encode("compound commitment", context.evidenceReceiptId)), "commitment");
        require(metadata == keccak256("compound metadata"), "metadata");
        require(keccak256(abi.encode(kernel.getGovernedObject(objectId))) == original, "historical record changed");
        require(kernel.nextRecognisedStateId() == nextState, "read formed recognition");

        (success, result) = address(kernel)
            .staticcall(abi.encodeWithSignature("getGovernedObjectCommitmentReference(uint256)", uint256(9999)));
        require(!success, "unknown object accepted");
        require(
            keccak256(result)
                == keccak256(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, uint256(9999))),
            "unknown object error changed"
        );
        requestVm.prank(VERIFIER_ACTOR);
        uint256 stateId = kernel.formChallengeableState(input, keccak256("legal continuation"), "test:continue");
        require(kernel.getRecognisedStateReference(stateId).governedObjectId == objectId, "legal formation blocked");
        require(keccak256(abi.encode(kernel.getGovernedObject(objectId))) == original, "formation changed object");
    }

    function testFormationAndChallengeableKeepActorAndSeparateVesting() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, keccak256("challengeable reason"), "test:challengeable");
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(id);
        require(state.status == AVACoreTypes.RecognisedStateStatus.Challengeable, "two steps only");
        require(state.subjectId == _authority(ROLE_SOURCE), "original subject");
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(_transitionInput(id, AVACoreTypes.RecognisedStateStatus.Vested));
        require(
            kernel.getRecognisedStateReference(id).status == AVACoreTypes.RecognisedStateStatus.Vested, "separate vest"
        );
    }

    function testHookReentryAndVetoRollbackLeaveGuardReusable() public {
        CompoundReentryHook hook = new CompoundReentryHook(kernel);
        kernel.bindPostTransitionHook(requestPackageId, address(hook));
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 nextTransition = kernel.nextTransitionId();
        hook.setVeto(true);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert(CompoundReentryHook.HookVeto.selector);
        kernel.formChallengeableState(input, keccak256("challengeable reason"), "test:challengeable");
        require(
            kernel.nextRecognisedStateId() == nextState && kernel.nextTransitionId() == nextTransition,
            "veto retained partial history"
        );
        require(hook.refusals() == 0, "veto retained hook changes");
        hook.setVeto(false);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, keccak256("challengeable reason"), "test:challengeable");
        require(id == nextState && hook.refusals() == 2, "retry did not retain two fenced hooks");
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(_transitionInput(id, AVACoreTypes.RecognisedStateStatus.Vested));
        require(hook.refusals() == 3, "independent vest stayed locked");
    }

    function testFormationCallCostAndSequentialCompounds() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory first = _newInput();
        AVAGovernanceKernel.RecognisedStateFormationInput memory second = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 beforeGas = gasleft();
        uint256 firstId = kernel.formChallengeableState(first, keccak256("challengeable reason"), "test:challengeable");
        uint256 cost = beforeGas - gasleft();
        emit log_named_uint("compound formation call gas", cost);
        require(cost <= 1_140_000, "compound formation call budget");
        requestVm.prank(VERIFIER_ACTOR);
        uint256 secondId =
            kernel.formChallengeableState(second, keccak256("challengeable reason"), "test:challengeable");
        require(
            secondId != firstId
                && kernel.getRecognisedStateReference(secondId).status
                    == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "sequential call stayed locked"
        );
        require(
            kernel.getRecognisedStateTransition(kernel.getRecognisedStateReference(firstId).lastTransitionId)
            .recognisedStateId == firstId,
            "first history lost"
        );
    }

    function testCompoundRetainsBothEventsReasonsHooksAndExactLegacyHistory() public {
        CompoundHistoryHook hook = new CompoundHistoryHook(address(kernel));
        kernel.bindPostTransitionHook(requestPackageId, address(hook));
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        uint256 snapshot = vm.snapshotState();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 oldId = kernel.formRecognisedState(input);
        AVAGovernanceKernel.RecognisedStateTransitionInput memory next =
            _transitionInput(oldId, AVACoreTypes.RecognisedStateStatus.Challengeable);
        next.reasonHash = keccak256("challengeable reason");
        next.reasonURI = "test:challengeable";
        requestVm.prank(VERIFIER_ACTOR);
        uint256 oldLast = kernel.transitionRecognisedState(next);
        bytes32 oldState = keccak256(abi.encode(kernel.getRecognisedState(oldId)));
        bytes32 first = keccak256(abi.encode(kernel.getRecognisedStateTransition(oldLast - 1)));
        bytes32 second = keccak256(abi.encode(kernel.getRecognisedStateTransition(oldLast)));
        require(vm.revertToState(snapshot), "snapshot restored");
        vm.recordLogs();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, next.reasonHash, next.reasonURI);
        require(keccak256(abi.encode(kernel.getRecognisedState(id))) == oldState, "same state and actor");
        uint256 last = kernel.getRecognisedStateReference(id).lastTransitionId;
        require(keccak256(abi.encode(kernel.getRecognisedStateTransition(last - 1))) == first, "formation history");
        require(keccak256(abi.encode(kernel.getRecognisedStateTransition(last))) == second, "transition history");
        require(
            hook.count() == 2 && hook.get(0).transitionId == last - 1 && hook.get(1).transitionId == last, "two hooks"
        );
        uint256 formed;
        uint256 transitioned;
        CompoundVm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(kernel)) continue;
            if (
                logs[i].topics[0]
                    == keccak256("RecognisedStateFormed(uint256,uint256,bytes32,uint256,uint8,uint8,uint256,address)")
            ) ++formed;
            if (
                logs[i].topics[0]
                    == keccak256(
                        "RecognisedStateTransitioned(uint256,uint256,bytes32,uint8,uint8,uint8,uint256,bytes32,address)"
                    )
            ) ++transitioned;
        }
        require(formed == 1 && transitioned == 2, "original events retained");
    }

    function testSecondPermissionRefusalRollsBackThenLegalCompoundCompletes() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        authorityMatrix.setPermission(
            requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE, false
        );
        uint256 beforeState = kernel.nextRecognisedStateId();
        uint256 beforeTransition = kernel.nextTransitionId();
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        require(
            kernel.nextRecognisedStateId() == beforeState && kernel.nextTransitionId() == beforeTransition,
            "atomic counters"
        );
        require(!kernel.recognisedStateUseStartedByPackage(requestPackageId), "no partial use");
        authorityMatrix.setPermission(
            requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE, true
        );
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        require(
            kernel.getRecognisedStateReference(id).status == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "restored authority"
        );
    }

    function testCustomTimingVetoRollsBackHookAndThenSucceedsAfterWait() public {
        CompoundHistoryHook hook = new CompoundHistoryHook(address(kernel));
        kernel.bindPostTransitionHook(requestPackageId, address(hook));
        kernel.bindTransitionGuard(requestPackageId, address(new CompoundTimeGuard(block.timestamp + 10)));
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        require(hook.count() == 0 && kernel.nextRecognisedStateId() == 1, "no partial hook or state");
        requestVm.warp(block.timestamp + 10);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        require(
            hook.count() == 2
                && kernel.getRecognisedStateReference(id).status == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "time rule satisfied"
        );
    }

    function testSecondStepRechecksPermissionAfterFormationHook() public {
        CompoundRevocationHook hook = new CompoundRevocationHook(authorityMatrix, requestAppId, ROLE_VERIFIER);
        kernel.bindPostTransitionHook(requestPackageId, address(hook));
        applicationRegistry.proposeApplicationAdmin(requestAppId, address(hook));
        hook.acceptAdmin();
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        require(kernel.nextRecognisedStateId() == 1 && kernel.nextTransitionId() == 1, "second-step refusal atomic");
        require(
            authorityMatrix.isAuthorised(
                VERIFIER_ACTOR, requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE
            ),
            "hook revocation also rolled back"
        );
        // This app can still choose separate steps and explicitly restore permission between them.
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formRecognisedState(input);
        require(
            !authorityMatrix.isAuthorised(
                VERIFIER_ACTOR, requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE
            ),
            "separate formation kept hook effect"
        );
        authorityMatrix.setPermission(
            requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_TRANSITION_RECOGNISED_STATE, true
        );
        requestVm.prank(VERIFIER_ACTOR);
        kernel.transitionRecognisedState(_transitionInput(id, AVACoreTypes.RecognisedStateStatus.Challengeable));
    }

    function testWrongActorStatusOrSecondReasonCannotCreatePartialRecognition() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory input = _newInput();
        requestVm.expectRevert();
        requestVm.prank(SOURCE_ACTOR);
        kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        input.status = AVACoreTypes.RecognisedStateStatus.Vested;
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.formChallengeableState(input, keccak256("next reason"), "test:next");
        input.status = AVACoreTypes.RecognisedStateStatus.Provisional;
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        kernel.formChallengeableState(input, bytes32(0), "test:next");
        require(kernel.nextRecognisedStateId() == 1 && kernel.nextTransitionId() == 1, "no partial recognition");
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formRecognisedState(input);
        requestVm.prank(VERIFIER_ACTOR);
        kernel.transitionRecognisedState(_transitionInput(id, AVACoreTypes.RecognisedStateStatus.Challengeable));
    }

    function testCompoundUsesActualIdAfterAnotherStateWasCreated() public {
        AVAGovernanceKernel.RecognisedStateFormationInput memory firstInput = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 earlier = kernel.formRecognisedState(firstInput);
        AVAGovernanceKernel.RecognisedStateFormationInput memory nextInput = _newInput();
        requestVm.prank(VERIFIER_ACTOR);
        uint256 id = kernel.formChallengeableState(nextInput, keccak256("next reason"), "test:next");
        require(
            id != earlier && kernel.getRecognisedStateReference(id).governedObjectId == nextInput.governedObjectId,
            "actual returned identity"
        );
        require(
            kernel.getRecognisedStateReference(earlier).status == AVACoreTypes.RecognisedStateStatus.Provisional,
            "other history untouched"
        );
    }

    function _newInput() private returns (AVAGovernanceKernel.RecognisedStateFormationInput memory input) {
        requestVm.startPrank(SOURCE_ACTOR);
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput(
                requestAppId,
                REQUEST_WORKFLOW,
                requestPackageId,
                ROLE_SOURCE,
                _authority(ROLE_SOURCE),
                keccak256("synthetic compound evidence"),
                keccak256("compound evidence"),
                requestPolicyId,
                _authority(ROLE_SOURCE),
                "test:compound-evidence"
            )
        );
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput(
                requestAppId,
                REQUEST_WORKFLOW,
                requestPackageId,
                ROLE_SOURCE,
                requestObjectTypeKey,
                keccak256(abi.encode("compound commitment", evidence)),
                0,
                _authority(ROLE_SOURCE),
                evidence,
                requestPolicyId,
                keccak256("compound metadata"),
                _authority(ROLE_SOURCE),
                "test:compound-object"
            )
        );
        requestVm.stopPrank();
        input = AVAGovernanceKernel.RecognisedStateFormationInput(
            objectId,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            AVACoreTypes.Stage.Verification,
            AVACoreTypes.RecognisedStateStatus.Provisional,
            keccak256("formation reason"),
            "test:formation"
        );
    }
}
