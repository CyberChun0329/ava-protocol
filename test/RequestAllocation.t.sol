// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {IAVAAllocationPolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface ExactRequestRevertVm {
    function expectRevert(bytes calldata data) external;
}

/// @notice Application vocabulary and actor checks run through the real package router.
contract RequestTestApplicationModule is IAVAApplicationModule, RuleModuleIdentity {
    bytes32 public immutable APP_ID;
    bytes32 private immutable objectType;
    bytes32 private immutable response;
    bytes32 private constant SOURCE_ROLE = keccak256("ava.test.request.role.source.v1");
    bytes32 private constant VERIFIER_ROLE = keccak256("ava.test.request.role.verifier.v1");
    bytes32 private constant ALLOCATOR_ROLE = keccak256("ava.test.request.role.allocator.v1");

    constructor(bytes32 appId, bytes32 objectType_, bytes32 response_) {
        APP_ID = appId;
        objectType = objectType_;
        response = response_;
    }

    function applicationId() external view returns (bytes32) {
        return APP_ID;
    }

    function validateGovernedObject(GovernedObjectContext calldata c) external view {
        require(c.appId == APP_ID && c.objectTypeKey == objectType && c.roleKey == SOURCE_ROLE, "object policy");
        require(c.parentObjectId == 0 && c.subjectId == c.authorityId && c.actor == address(0xC1), "source policy");
    }

    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata c) external view {
        require(c.appId == APP_ID && c.objectTypeKey == objectType && c.roleKey == VERIFIER_ROLE, "formation policy");
        require(
            c.stage == AVACoreTypes.Stage.Verification && c.status == AVACoreTypes.RecognisedStateStatus.Provisional,
            "formation status"
        );
    }

    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata c) external view {
        require(c.appId == APP_ID && c.objectTypeKey == objectType && c.roleKey == VERIFIER_ROLE, "transition policy");
    }

    function validateEvidence(EvidenceContext calldata c) external view {
        require(c.appId == APP_ID && c.roleKey == SOURCE_ROLE && c.subjectId == c.authorityId, "evidence policy");
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata c) external view {
        require(c.appId == APP_ID && c.objectTypeKey == objectType, "record app");
        require(c.actionKey == AVACoreTypes.ACTION_RECORD_ALLOCATION && c.roleKey == ALLOCATOR_ROLE, "record action");
        require(c.recordTypeKey == response && c.actor == address(0xA1), "record operation or actor");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(APP_ID, objectType, response));
    }
}

contract RejectRequestAllocationPolicy is IAVAAllocationPolicyModule, IAVARequestPolicy, RuleModuleIdentity {
    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external pure {
        require(request.exactCommitment && witness.length == 1, "test exact support");
    }

    function validateRequestAllocation(RequestContext calldata, Witness[] calldata, DecisionContext calldata)
        external
        pure {}

    function validateAllocation(AllocationPolicyContext calldata) external pure {
        revert("allocation policy rejected");
    }
}

/// @notice Exercises the kernel's public, identity-bound transition requester seam.
contract RequestStateTransitionRequester is RuleModuleIdentity {
    function change(AVAGovernanceKernel kernel, AVAGovernanceKernel.SourceBoundTransitionInput calldata input)
        external
        returns (uint256)
    {
        return kernel.requestSourceBoundTransition(input);
    }
}

contract RequestExecutor {
    function execute(AVARequestAllocation extension, uint256 id, bytes32 response, bytes32 parameters, bool fail)
        external
    {
        extension.consume(id, response, parameters, msg.sender);
        require(!fail, "external execution failed");
        extension.complete(id, keccak256(abi.encode(id, response, parameters)));
    }
}

contract RequestAllocationTest is RequestAllocationFixture {
    event log_named_uint(string key, uint256 value);
    bytes32 private constant APP = keccak256("request.test.app");
    bytes32 private constant RESPONSE = keccak256("request.test.response");
    bytes32 private constant PARAMETERS = keccak256("request.test.parameters");
    bytes32 private constant BURDEN = keccak256("request.test.burden");
    bytes32 private constant OBJECT = keccak256("request.test.object");
    RequestExecutor private executor;
    RequestTestApplicationModule private application;
    RequestStateTransitionRequester private transitionRequester;

    function setUp() public {
        application = new RequestTestApplicationModule(APP, OBJECT, RESPONSE);
        _setUpRequestAllocation(APP, application, OBJECT);
        executor = new RequestExecutor();
        transitionRequester = new RequestStateTransitionRequester();
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
    }

    function testSuccessfulAtomicLifecycleStoresOriginalAllocatorAndTrigger() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 id = _createRequest(input);
        _approveRequest(id);
        require(requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)), "not executable");
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.consumed && record.completed && record.effectHash != bytes32(0), "lifecycle missing");
        require(record.creator == SOURCE_ACTOR && record.allocator == ALLOCATOR_ACTOR, "actor history missing");
        require(record.triggeredBy == address(this), "trigger missing");
        require(
            record.recognisedStateTransitionId
                == kernel.getRecognisedStateReference(input.recognisedStateId).lastTransitionId,
            "source history missing"
        );
    }

    function testConsumedMeaningCannotReplayThroughFreshExactRecognition() public {
        uint256 consumedId = _createRequest(_input());
        _approveRequest(consumedId);
        executor.execute(requestAllocation, consumedId, RESPONSE, PARAMETERS, false);
        requestVm.warp(block.timestamp + 1); // New expiry permits a distinct object commitment, not another effect.
        uint256 freshId = _createRequest(_input());
        require(freshId != consumedId, "fresh historical request");
        ExactRequestRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, freshId));
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.approve(freshId, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        require(requestAllocation.getRequest(consumedId).completed, "effect history lost");
    }

    function testConsumedExactMeaningCannotSwitchToScopedMode() public {
        uint256 consumedId = _createRequest(_input());
        _approveRequest(consumedId);
        executor.execute(requestAllocation, consumedId, RESPONSE, PARAMETERS, false);
        requestVm.warp(block.timestamp + 1);
        AVARequestAllocation.RequestInput memory fresh = _input();
        require(fresh.recognisedStateId != consumedId, "discriminating source identity");
        IAVARequestPolicy.WitnessInput[] memory witness = new IAVARequestPolicy.WitnessInput[](1);
        witness[0] = IAVARequestPolicy.WitnessInput(
            fresh.recognisedStateId,
            kernel.getRecognisedStateReference(fresh.recognisedStateId).lastTransitionId,
            IAVARequestPolicy.RecognitionScope(PARAMETERS, RESPONSE, BURDEN)
        );
        ExactRequestRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, consumedId));
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.createSupportedRequest(fresh, witness, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function testCreationRequiresAppScopedAuthority() public {
        AVARequestAllocation.RequestInput memory input = _input();
        requestVm.expectRevert();
        requestAllocation.createRequest(input, ROLE_SOURCE, _authority(ROLE_SOURCE));
        bytes32 otherApp = keccak256("request.other.app");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other.identity"), keccak256("other.authority"), address(this), "test:other"
        );
        bytes32 otherAuthority = keccak256("other.source");
        identityRegistry.assignSubject(address(this), otherApp, ROLE_SOURCE, otherAuthority, "test:other-source");
        authorityMatrix.setPermission(otherApp, ROLE_SOURCE, requestAllocation.ACTION_CREATE_REQUEST(), true);
        requestVm.expectRevert();
        requestAllocation.createRequest(input, ROLE_SOURCE, otherAuthority);
    }

    function testAllocationRequiresAppScopedOriginalAuthority() public {
        uint256 id = _createRequest(_input());
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_SOURCE));
        _approveRequest(id);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testAllocationUsesHistoricalAllocationPolicy() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(new RejectRequestAllocationPolicy()));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:reject"
            ),
            requestPackageId,
            bindings
        );
        uint256 id = _createRequest(_input());
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testCommitmentBindsAppExecutorOperationParametersBurdenAndExpiry() public {
        AVARequestAllocation.RequestInput memory input = _input();
        AVARequestAllocation.RequestInput memory changed = _copy(input);
        changed.parametersHash = keccak256("wrong.parameters");
        _expectCreationRevert(changed);
        changed = _copy(input);
        changed.responseClass = keccak256("wrong.response");
        _expectCreationRevert(changed);
        changed = _copy(input);
        changed.executor = address(new RequestExecutor());
        _expectCreationRevert(changed);
        changed = _copy(input);
        changed.burdenHash = keccak256("wrong.burden");
        _expectCreationRevert(changed);
        changed = _copy(input);
        changed.validUntil += 1;
        _expectCreationRevert(changed);
        changed = _copy(input);
        uint256 wrongState = _createStateForCommitment(
            requestAllocation.commitmentFor(
                keccak256("wrong.app"),
                input.executor,
                input.responseClass,
                input.parametersHash,
                input.burdenHash,
                input.validUntil
            )
        );
        changed.recognisedStateId = wrongState;
        _expectCreationRevert(changed);
        _approveRequest(_createRequest(input));
    }

    function testCommitmentDomainBindsChainAndExtension() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 initial = requestAllocation.commitmentFor(APP, address(executor), RESPONSE, PARAMETERS, BURDEN, expiry);
        AVARequestAllocation another = new AVARequestAllocation(kernel);
        require(
            initial != another.commitmentFor(APP, address(executor), RESPONSE, PARAMETERS, BURDEN, expiry),
            "extension omitted"
        );
        requestVm.chainId(block.chainid + 1);
        require(
            initial != requestAllocation.commitmentFor(APP, address(executor), RESPONSE, PARAMETERS, BURDEN, expiry),
            "chain omitted"
        );
    }

    function testCreationRejectsMissingMeaningAndNonContractExecutor() public {
        AVARequestAllocation.RequestInput memory input = _input();
        input.executor = address(0);
        _expectCreationRevert(input);
        input.executor = address(0xD1);
        _expectCreationRevert(input);
        input.executor = address(executor);
        input.responseClass = bytes32(0);
        _expectCreationRevert(input);
        input.responseClass = RESPONSE;
        input.parametersHash = bytes32(0);
        _expectCreationRevert(input);
        input.parametersHash = PARAMETERS;
        input.burdenHash = bytes32(0);
        _expectCreationRevert(input);
        input.burdenHash = BURDEN;
        input.validUntil = uint64(block.timestamp);
        _expectCreationRevert(input);
    }

    function testRevokedCreatorCannotCancelUnapprovedRequest() public {
        uint256 id = _createRequest(_input());
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_CREATE_REQUEST(), false);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        require(!requestAllocation.getRequest(id).cancelled, "revoked creator cancelled");
    }

    function testFreshSubjectAtSameCreatorAddressDoesNotInheritCancellation() public {
        uint256 id = _createRequest(_input());
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.assignSubject(
            SOURCE_ACTOR, APP, ROLE_SOURCE, keccak256("replacement.creator.subject"), "test:replacement"
        );
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        require(!requestAllocation.getRequest(id).cancelled, "new identity inherited old cancellation");
    }

    function testSameStateCannotCreateDuplicateEvenAfterCancellation() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 id = _createRequest(input);
        _expectCreationRevert(input);
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.cancel(id);
        _expectCreationRevert(input);
    }

    function testNonVestedSourceCannotCreateRequest() public {
        AVARequestAllocation.RequestInput memory input = _input();
        _changeState(
            input.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _expectCreationRevert(input);
    }

    function testVestedAttributionIsNotVerificationSupport() public {
        requestPackageId = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 2);
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 objectId = kernel.getRecognisedStateReference(input.recognisedStateId).governedObjectId;
        requestVm.prank(VERIFIER_ACTOR);
        uint256 otherStage = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Attribution,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: keccak256("other-stage"),
                reasonURI: "test:other-stage"
            })
        );
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(_transitionInput(otherStage, AVACoreTypes.RecognisedStateStatus.Vested));
        input.recognisedStateId = otherStage;
        _expectCreationRevert(input);
    }

    function testExecutionRejectsUnapprovedWrongResponseParametersAndExecutor() public {
        uint256 id = _createRequest(_input());
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
        _approveRequest(id);
        _expectExecutionRevert(id, keccak256("wrong.response"), PARAMETERS, address(executor));
        _expectExecutionRevert(id, RESPONSE, keccak256("wrong.parameters"), address(executor));
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(this));
        requestVm.expectRevert();
        requestAllocation.consume(id, RESPONSE, PARAMETERS, address(this));
        requestVm.expectRevert();
        requestAllocation.complete(id, keccak256("effect"));
    }

    function testExecutionRejectsRevokedAllocatorPermission() public {
        uint256 id = _approved();
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testExecutionRejectsInactiveAllocatorSubject() public {
        uint256 id = _approved();
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testReplacementAllocatorAtSameAddressNeedsFreshDecision() public {
        uint256 oldId = _approved();
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(oldId);
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        bytes32 replacement = keccak256("allocator.replacement.subject");
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, replacement, "test:replacement");
        _expectExecutionRevert(oldId, RESPONSE, PARAMETERS, address(executor));
        require(
            requestAllocation.getRequest(oldId).allocatorAuthorityId == original.allocatorAuthorityId,
            "approval rewritten"
        );
        requestVm.warp(block.timestamp + 1);
        uint256 freshId = _createRequest(_input());
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.approve(freshId, ROLE_ALLOCATOR, replacement);
        executor.execute(requestAllocation, freshId, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(freshId).allocatorAuthorityId == replacement, "new decision identity lost");
        require(!requestAllocation.getRequest(oldId).consumed, "old approval revived");
    }

    function testExecutionRejectsInactiveSourceSubject() public {
        uint256 id = _approved();
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testExecutionRejectsRevokedEvidence() public {
        uint256 id = _approved();
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
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testExecutionRejectsChangedTransitionEvenAfterSourceIsVestedAgain() public {
        uint256 id = _approved();
        uint256 stateId = requestAllocation.getRequest(id).input.recognisedStateId;
        _changeState(
            stateId, AVACoreTypes.RecognisedStateStatus.Voided, AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
        _changeState(stateId, AVACoreTypes.RecognisedStateStatus.Challengeable, AVACoreTypes.TransitionKind.Restoration);
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Vested));
        require(
            kernel.getRecognisedStateReference(stateId).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "not vested again"
        );
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testRestoredSourceRequiresFreshAllocationAndPreservesOldDecision() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 oldId = _createRequest(input);
        _approveRequest(oldId);
        uint256 oldTransition = requestAllocation.getRequest(oldId).recognisedStateTransitionId;
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        _expectExecutionRevert(oldId, RESPONSE, PARAMETERS, address(executor));

        uint256 newId = _createRequest(input);
        require(newId != oldId, "old request overwritten");
        require(requestAllocation.getRequest(newId).supersedesRequestId == oldId, "predecessor missing");
        require(requestAllocation.requestIdByRecognisedState(input.recognisedStateId) == newId, "latest missing");
        require(requestAllocation.getRequest(newId).allocator == address(0), "old allocation reused");
        _expectExecutionRevert(newId, RESPONSE, PARAMETERS, address(executor));
        _expectCreationRevert(input);
        _approveRequest(newId);
        executor.execute(requestAllocation, newId, RESPONSE, PARAMETERS, false);

        AVARequestAllocation.RequestRecord memory oldRecord = requestAllocation.getRequest(oldId);
        require(oldRecord.recognisedStateTransitionId == oldTransition, "source history overwritten");
        require(oldRecord.allocator == ALLOCATOR_ACTOR && !oldRecord.consumed, "old decision overwritten");
        _expectExecutionRevert(oldId, RESPONSE, PARAMETERS, address(executor));
    }

    function testExactWitnessHistoryAndMeasuredLifecycle() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 transition = kernel.getRecognisedStateReference(input.recognisedStateId).lastTransitionId;
        bytes32 commitment =
            requestAllocation.commitmentFor(APP, address(executor), RESPONSE, PARAMETERS, BURDEN, input.validUntil);
        uint256 start = gasleft();
        uint256 id = _createRequest(input);
        emit log_named_uint("exact create call gas", start - gasleft());

        IAVARequestPolicy.WitnessInput[] memory expected = new IAVARequestPolicy.WitnessInput[](1);
        expected[0] = IAVARequestPolicy.WitnessInput(
            input.recognisedStateId, transition, IAVARequestPolicy.RecognitionScope(commitment, RESPONSE, BURDEN)
        );
        bytes32 expectedHash =
            keccak256(abi.encode(block.chainid, address(requestAllocation), id, commitment, expected));
        require(
            keccak256(abi.encode(requestAllocation.getSupportWitness(id))) == keccak256(abi.encode(expected)), "witness"
        );
        require(requestAllocation.supportWitnessHash(id) == expectedHash, "witness hash");
        require(!requestAllocation.SUPPORT().occurrenceChanged(id), "occurrence changed early");

        start = gasleft();
        _approveRequest(id);
        emit log_named_uint("exact approve call gas", start - gasleft());
        start = gasleft();
        require(requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)), "not executable");
        emit log_named_uint("exact validation call gas", start - gasleft());

        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        require(requestAllocation.SUPPORT().occurrenceChanged(id), "changed occurrence missed");
        require(
            keccak256(abi.encode(requestAllocation.getSupportWitness(id))) == keccak256(abi.encode(expected)),
            "history changed"
        );
        require(requestAllocation.supportWitnessHash(id) == expectedHash, "historical hash changed");
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testRestoredSourceCanSupportItsFirstRequest() public {
        AVARequestAllocation.RequestInput memory input = _input();
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        uint256 id = _createRequest(input);
        _approveRequest(id);
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
    }

    function testFreshVestingAfterCorrectionAlsoRequiresFreshAllocation() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 oldId = _createRequest(input);
        _approveRequest(oldId);
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Challengeable);
        requestVm.prank(VERIFIER_ACTOR);
        kernel.vestRecognisedState(_transitionInput(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Vested));
        uint256 newId = _createRequest(input);
        _expectExecutionRevert(oldId, RESPONSE, PARAMETERS, address(executor));
        _expectExecutionRevert(newId, RESPONSE, PARAMETERS, address(executor));
        _approveRequest(newId);
        executor.execute(requestAllocation, newId, RESPONSE, PARAMETERS, false);
    }

    function testConsumedRequestCannotBeReauthorisedAfterRestoration() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 id = _createRequest(input);
        _approveRequest(id);
        requestVm.prank(address(executor));
        requestAllocation.consume(id, RESPONSE, PARAMETERS, address(this));
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        _expectCreationRevert(input);
        require(requestAllocation.requestIdByRecognisedState(input.recognisedStateId) == id, "consumption lost");
        requestVm.prank(address(executor));
        requestAllocation.complete(id, keccak256("effect recorded after correction"));
        require(requestAllocation.getRequest(id).completed, "later effect record blocked");
    }

    function testRepeatedRestorationRetainsAncestryAndCannotRepeatConsumedEffect() public {
        AVARequestAllocation.RequestInput memory input = _input();
        uint256 firstId = _createRequest(input);
        _approveRequest(firstId);
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        uint256 secondId = _createRequest(input);
        _approveRequest(secondId);
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        uint256 thirdId = _createRequest(input);
        require(requestAllocation.getRequest(thirdId).supersedesRequestId == secondId, "second missing");
        require(requestAllocation.getRequest(secondId).supersedesRequestId == firstId, "first missing");
        _expectExecutionRevert(firstId, RESPONSE, PARAMETERS, address(executor));
        _expectExecutionRevert(secondId, RESPONSE, PARAMETERS, address(executor));
        _approveRequest(thirdId);
        executor.execute(requestAllocation, thirdId, RESPONSE, PARAMETERS, false);
        _restoreSource(input.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored);
        _expectCreationRevert(input);
    }

    function testHistoricalPackageRemainsBindingAfterNewVersion() public {
        uint256 id = _approved();
        uint256 historicalPackage = requestPackageId;
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(new RejectRequestAllocationPolicy()));
        uint256 latest = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:new-reject-policy"
            ),
            historicalPackage,
            bindings
        );
        require(latest != historicalPackage, "no newer package");
        require(requestAllocation.getRequest(id).packageId == historicalPackage, "history rewritten");
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
    }

    function testHistoricalModuleIdentityDriftBlocksExecution() public {
        uint256 id = _approved();
        requestVm.etch(address(application), hex"00");
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
    }

    function testExpiryBoundaryBlocksExecutionWithoutAdverseState() public {
        uint256 id = _approved();
        AVARequestAllocation.RequestRecord memory beforeRecord = requestAllocation.getRequest(id);
        requestVm.warp(beforeRecord.input.validUntil);
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
        require(
            kernel.getRecognisedStateReference(beforeRecord.input.recognisedStateId).status
                == AVACoreTypes.RecognisedStateStatus.Vested,
            "expiry changed recognised state"
        );
        require(!requestAllocation.getRequest(id).consumed, "expired consumed");
    }

    function testCreatorCanAbandonOnlyBeforeApproval() public {
        uint256 id = _createRequest(_input());
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.cancel(id);
        _expectExecutionRevert(id, RESPONSE, PARAMETERS, address(executor));
        require(requestAllocation.getRequest(id).cancelled, "cancel missing");
        require(
            kernel.getRecognisedStateReference(requestAllocation.getRequest(id).input.recognisedStateId).status
                == AVACoreTypes.RecognisedStateStatus.Vested,
            "cancel changed recognised state"
        );
    }

    function testApprovedRequestCannotBeCancelledByCreatorOrRevokedAllocator() public {
        uint256 id = _approved();
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
        require(!requestAllocation.getRequest(id).cancelled, "approved decision abandoned");
    }

    function testCompletionRequiresConsumptionAndBoundExecutorAndIsOnceOnly() public {
        uint256 id = _approved();
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.complete(id, keccak256("effect"));
        requestVm.prank(address(executor));
        requestAllocation.consume(id, RESPONSE, PARAMETERS, address(this));
        requestVm.expectRevert();
        requestAllocation.complete(id, keccak256("effect"));
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.complete(id, bytes32(0));
        requestVm.prank(address(executor));
        requestAllocation.complete(id, keccak256("effect"));
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.complete(id, keccak256("another.effect"));
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.cancel(id);
    }

    function testCompletedRequestCannotReplay() public {
        uint256 id = _approved();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
    }

    function testExternalExecutionRevertRollsConsumptionBack() public {
        uint256 id = _approved();
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, true);
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(!record.consumed && !record.completed && record.triggeredBy == address(0), "consume not rolled back");
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS, false);
        require(requestAllocation.getRequest(id).completed, "retry did not complete");
    }

    function _approved() private returns (uint256 id) {
        id = _createRequest(_input());
        _approveRequest(id);
    }

    function _copy(AVARequestAllocation.RequestInput memory input)
        private
        pure
        returns (AVARequestAllocation.RequestInput memory)
    {
        return AVARequestAllocation.RequestInput(
            input.recognisedStateId,
            input.executor,
            input.responseClass,
            input.parametersHash,
            input.burdenHash,
            input.validUntil
        );
    }

    function _expectCreationRevert(AVARequestAllocation.RequestInput memory input) private {
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createRequest(input, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectExecutionRevert(uint256 id, bytes32 response, bytes32 parameters, address executor_) private {
        requestVm.expectRevert();
        requestAllocation.validateExecution(id, response, parameters, executor_);
    }

    function _changeState(uint256 stateId, AVACoreTypes.RecognisedStateStatus status, AVACoreTypes.TransitionKind kind)
        private
    {
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(stateId);
        transitionRequester.change(
            kernel,
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: stateId,
                expectedTransitionId: state.lastTransitionId,
                decisionPackageId: state.packageId,
                sourceRecordId: 1,
                decisionEvidenceReceiptId: state.evidenceReceiptId,
                disclosureTargetId: state.governedObjectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                actionKey: kind == AVACoreTypes.TransitionKind.ChallengeCorrection
                    ? AVACoreTypes.ACTION_RESOLVE_CHALLENGE
                    : AVACoreTypes.ACTION_APPLY_RESTORATION,
                decisionHash: keccak256("request.changed.decision"),
                toStatus: status,
                kind: kind,
                reasonHash: keccak256(abi.encode(stateId, status)),
                reasonURI: "test:changed-state"
            })
        );
    }

    function _restoreSource(uint256 stateId, AVACoreTypes.RecognisedStateStatus restoredStatus) private {
        _changeState(
            stateId, AVACoreTypes.RecognisedStateStatus.Voided, AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _changeState(stateId, restoredStatus, AVACoreTypes.TransitionKind.Restoration);
    }

    function _input() private returns (AVARequestAllocation.RequestInput memory input) {
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 stateId = _createRequestState(address(executor), RESPONSE, PARAMETERS, BURDEN, expiry);
        return AVARequestAllocation.RequestInput(stateId, address(executor), RESPONSE, PARAMETERS, BURDEN, expiry);
    }
}
