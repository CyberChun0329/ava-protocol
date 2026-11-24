// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVAAllocationPolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVARequestAllocation, AVARequestCorrectionActions} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";

interface RequestSupportVm {
    function expectRevert(bytes calldata revertData) external;
}

library RequestSupportDomain {
    bytes32 internal constant APP = keccak256("scoped.request.app");
    bytes32 internal constant WORKFLOW = keccak256("ava.test.request.workflow.v1");
    bytes32 internal constant OBJECT = keccak256("scoped.request.object");
    bytes32 internal constant SOURCE_ROLE = keccak256("ava.test.request.role.source.v1");
    bytes32 internal constant VERIFIER_ROLE = keccak256("ava.test.request.role.verifier.v1");
    bytes32 internal constant ALLOCATOR_ROLE = keccak256("ava.test.request.role.allocator.v1");
    bytes32 internal constant RELEASE = keccak256("scoped.request.release");
    bytes32 internal constant PRIORITY = keccak256("scoped.request.priority");
    bytes32 internal constant COMPLETION_CLAIM = keccak256("domain.claim.completed-deliverable");
    bytes32 internal constant REVIEW_CLAIM = keccak256("domain.claim.independent-review");
    // This domain expressly permits these recognitions to support either bounded response.
    // It is deliberately distinct from either response class.
    bytes32 internal constant TWO_RESPONSE_USE = keccak256("domain.use.release-or-priority");
    bytes32 internal constant STANDARD_EVIDENCE = keccak256("domain.evidence.standard");
    bytes32 internal constant STRONG_EVIDENCE = keccak256("domain.evidence.independent-replication");
    bytes32 internal constant RELEASE_BURDEN = keccak256("domain.request.release-burden");
    bytes32 internal constant RENEWED_RELEASE_BURDEN = keccak256("domain.request.renewed-release-burden");
    bytes32 internal constant PRIORITY_BURDEN = keccak256("domain.request.priority-burden");
}

/// @notice Test domain vocabulary; all Core identity, evidence and lifecycle checks remain real.
contract RequestSupportApplication is IAVAApplicationModule, RuleModuleIdentity {
    function applicationId() external pure returns (bytes32) {
        return RequestSupportDomain.APP;
    }

    function validateGovernedObject(GovernedObjectContext calldata c) external pure {
        require(c.appId == RequestSupportDomain.APP && c.objectTypeKey == RequestSupportDomain.OBJECT, "object");
        require(c.roleKey == RequestSupportDomain.SOURCE_ROLE && c.subjectId == c.authorityId, "source");
    }

    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata c) external pure {
        require(c.appId == RequestSupportDomain.APP && c.roleKey == RequestSupportDomain.VERIFIER_ROLE, "formation");
        require(c.stage == AVACoreTypes.Stage.Verification, "verification");
    }

    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata c) external pure {
        require(c.appId == RequestSupportDomain.APP && c.roleKey == RequestSupportDomain.VERIFIER_ROLE, "transition");
    }

    function validateEvidence(EvidenceContext calldata c) external pure {
        require(c.appId == RequestSupportDomain.APP && c.subjectId == c.authorityId, "evidence");
        require(
            c.roleKey == RequestSupportDomain.SOURCE_ROLE || c.roleKey == RequestSupportDomain.VERIFIER_ROLE,
            "evidence role"
        );
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata c) public view virtual {
        require(c.appId == RequestSupportDomain.APP && c.objectTypeKey == RequestSupportDomain.OBJECT, "record");
        require(
            c.recordTypeKey == RequestSupportDomain.RELEASE || c.recordTypeKey == RequestSupportDomain.PRIORITY,
            "response"
        );
        if (c.actionKey == AVACoreTypes.ACTION_RECORD_ALLOCATION) {
            require(c.roleKey == RequestSupportDomain.ALLOCATOR_ROLE, "allocation role");
        } else if (c.actionKey == AVARequestCorrectionActions.FILE) {
            require(c.roleKey == RequestSupportDomain.SOURCE_ROLE, "filing role");
        } else {
            require(
                c.actionKey == AVARequestCorrectionActions.RESOLVE
                    || c.actionKey == AVARequestCorrectionActions.AUTHORISE_REMEDY,
                "correction"
            );
            require(c.roleKey == RequestSupportDomain.VERIFIER_ROLE, "resolution role");
        }
    }
}

/// @notice The selected primary must supply the downstream identity, even when it is not first.
contract RequestSupportPrimaryApplication is RequestSupportApplication {
    AVAGovernanceKernel private immutable kernel;
    bytes32 private immutable primaryScopeHash;

    constructor(AVAGovernanceKernel kernel_, bytes32 primaryScopeHash_) {
        kernel = kernel_;
        primaryScopeHash = primaryScopeHash_;
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata c) public view override {
        super.validateDownstreamRecord(c);
        if (c.actionKey != AVACoreTypes.ACTION_RECORD_ALLOCATION) return;
        AVAGovernanceKernel.RecognisedStateReference memory source =
            kernel.getRecognisedStateReference(c.recognisedStateId);
        AVACoreTypes.GovernedObjectRecord memory objectRecord = kernel.getGovernedObject(c.governedObjectId);
        require(
            source.governedObjectId == c.governedObjectId && source.subjectId == c.subjectId
                && source.evidenceReceiptId == c.evidenceReceiptId && objectRecord.objectTypeKey == c.objectTypeKey
                && objectRecord.metadataHash == primaryScopeHash,
            "downstream primary identity"
        );
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(kernel, primaryScopeHash));
    }
}

/// @notice Immutable domain rule, selected by the application's real package authority.
/// A completion and an independent review jointly suffice; neither alone does.
/// Priority and the renewed release burden need stronger review evidence. No mutable eligibility flags are used.
contract RequestSupportPolicy is IAVARequestPolicy, IAVAAllocationPolicyModule, RuleModuleIdentity {
    address private immutable extension;
    address private immutable support;
    address private immutable executor;

    constructor(address extension_, address executor_) {
        extension = extension_;
        support = address(AVARequestAllocation(extension_).SUPPORT());
        executor = executor_;
    }

    function validateAllocation(AllocationPolicyContext calldata c) external pure {
        require(
            c.record.appId == RequestSupportDomain.APP && c.record.roleKey == RequestSupportDomain.ALLOCATOR_ROLE,
            "allocation scope"
        );
        require(c.units == 1, "allocation units");
    }

    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external view {
        _support(request, witness);
    }

    function validateRequestAllocation(
        RequestContext calldata request,
        Witness[] calldata witness,
        DecisionContext calldata decision
    ) external view {
        _support(request, witness);
        require(
            decision.roleKey == RequestSupportDomain.ALLOCATOR_ROLE && decision.authorityId != bytes32(0),
            "decision authority"
        );
        require(decision.actor == address(0xA1) && decision.evaluatedAt == block.timestamp, "decision actor");
    }

    function _support(RequestContext calldata request, Witness[] calldata witness) private view {
        require(
            (msg.sender == extension || msg.sender == support) && request.requestAllocation == extension, "extension"
        );
        require(
            request.appId == RequestSupportDomain.APP && request.workflowKey == RequestSupportDomain.WORKFLOW,
            "request scope"
        );
        require(!request.exactCommitment && request.executor == executor, "executor or mode");
        require(request.parametersHash != bytes32(0) && request.validUntil > block.timestamp, "request terms");
        bool priority = request.responseClass == RequestSupportDomain.PRIORITY;
        require(priority || request.responseClass == RequestSupportDomain.RELEASE, "response");
        require(
            request.burdenHash
                    == (priority ? RequestSupportDomain.PRIORITY_BURDEN : RequestSupportDomain.RELEASE_BURDEN)
                || (!priority && request.burdenHash == RequestSupportDomain.RENEWED_RELEASE_BURDEN),
            "request burden"
        );
        require(witness.length == 2, "joint pair required");
        require(
            witness[0].scope.claimHash == RequestSupportDomain.COMPLETION_CLAIM
                && witness[1].scope.claimHash == RequestSupportDomain.REVIEW_CLAIM,
            "claim matching"
        );
        for (uint256 i; i < witness.length; ++i) {
            require(witness[i].objectTypeKey == RequestSupportDomain.OBJECT, "object vocabulary");
            require(witness[i].scope.useHash == RequestSupportDomain.TWO_RESPONSE_USE, "bounded use");
        }
        require(witness[0].scope.burdenHash == RequestSupportDomain.STANDARD_EVIDENCE, "completion burden");
        bytes32 reviewBurden = witness[1].scope.burdenHash;
        require(
            reviewBurden == RequestSupportDomain.STRONG_EVIDENCE
                || (!priority
                    && request.burdenHash == RequestSupportDomain.RELEASE_BURDEN
                    && reviewBurden == RequestSupportDomain.STANDARD_EVIDENCE),
            "review burden"
        );
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(extension, support, executor));
    }
}

contract RequestSupportExecutor {
    function execute(AVARequestAllocation allocation, uint256 id, bytes32 response, bytes32 parameters) external {
        allocation.consume(id, response, parameters, msg.sender);
        allocation.complete(id, keccak256(abi.encode(id, response, parameters)));
    }
}

contract RequestSupportTransitionRequester is RuleModuleIdentity {
    function change(AVAGovernanceKernel kernel, AVAGovernanceKernel.SourceBoundTransitionInput calldata input)
        external
    {
        kernel.requestSourceBoundTransition(input);
    }
}

contract RequestSupportTest is RequestAllocationFixture {
    bytes32 private constant PARAMETERS = keccak256("scoped.request.parameters");
    RequestSupportApplication private application;
    RequestSupportPolicy private policy;
    RequestSupportExecutor private executor;
    RequestSupportTransitionRequester private transitionRequester;
    uint64 private ruleVersion = 1;

    event log_named_uint(string key, uint256 value);

    function setUp() public {
        application = new RequestSupportApplication();
        _setUpRequestAllocation(RequestSupportDomain.APP, application, RequestSupportDomain.OBJECT);
        executor = new RequestSupportExecutor();
        policy = new RequestSupportPolicy(address(requestAllocation), address(executor));
        // Install the typed policy before creating any source, using the real package authority.
        _installPolicy(address(policy));
        transitionRequester = new RequestSupportTransitionRequester();
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
        authorityMatrix.setPermission(requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
        authorityMatrix.setPermission(requestAppId, ROLE_SOURCE, AVARequestCorrectionActions.FILE, true);
        authorityMatrix.setPermission(requestAppId, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, true);
        authorityMatrix.setPermission(requestAppId, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
    }

    function testJointWitnessSupportRequiresSeparateApprovalThenExecutes() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        require(requestAllocation.scopedSupportByRequest(id), "mode");
        bytes32 support = requestAllocation.supportWitnessHash(id);
        require(support != bytes32(0) && requestAllocation.validateCurrentSupport(id) == support, "support binding");
        IAVARequestPolicy.WitnessInput[] memory retained = requestAllocation.getSupportWitness(id);
        require(keccak256(abi.encode(retained)) == keccak256(abi.encode(witness)), "witness changed");
        require(requestAllocation.getRequest(id).allocator == address(0), "support approved itself");
        _expectExecutionRevert(id, input);
        _approveRequest(id);
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.consumed && record.completed && record.effectHash != bytes32(0), "effect missing");
        require(record.allocator == ALLOCATOR_ACTOR && record.triggeredBy == address(this), "decision or trigger");
        require(requestAllocation.supportedRequestIdByMeaning(_meaning(input)) == id, "meaning binding");
    }

    function testSameSignerCreatesAndApprovesScopedRequest() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 predecessor = _createSupported(input, witness);
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.cancel(predecessor);
        bytes32 creatorAuthority = keccak256("allocator creator authority");
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, requestAppId, ROLE_SOURCE, creatorAuthority, "test:creator");
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 id = requestAllocation.createSupportedAndApproveRequest(
            input,
            witness,
            AVARequestAllocation.ScopedRequestAuthorities(
                ROLE_SOURCE, creatorAuthority, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
            )
        );
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.creator == ALLOCATOR_ACTOR && record.creatorAuthorityId == creatorAuthority, "creator");
        require(
            record.allocator == ALLOCATOR_ACTOR && record.allocatorAuthorityId == _authority(ROLE_ALLOCATOR),
            "allocator"
        );
        require(requestAllocation.scopedSupportByRequest(id), "scope");
        require(
            record.supersedesRequestId == predecessor && requestAllocation.supersededByRequest(predecessor) == id,
            "lineage"
        );
        require(
            keccak256(abi.encode(requestAllocation.getSupportWitness(id))) == keccak256(abi.encode(witness)), "witness"
        );
        require(requestAllocation.supportedRequestIdByMeaning(_meaning(input)) == id, "meaning");
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        require(requestAllocation.getRequest(id).completed, "effect");
    }

    function testSameSignerFailedApprovalRollsBackScopedCreation() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        bytes32 creatorAuthority = keccak256("allocator creator authority");
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, requestAppId, ROLE_SOURCE, creatorAuthority, "test:creator");
        uint256 nextId = requestAllocation.nextRequestId();
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createSupportedAndApproveRequest(
            input,
            witness,
            AVARequestAllocation.ScopedRequestAuthorities(ROLE_SOURCE, creatorAuthority, ROLE_ALLOCATOR, bytes32(0))
        );
        require(requestAllocation.nextRequestId() == nextId, "id reserved");
        require(requestAllocation.supportedRequestIdByMeaning(_meaning(input)) == 0, "meaning reserved");
        require(requestAllocation.supportWitnessHash(nextId) == bytes32(0), "support retained");
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 id = requestAllocation.createSupportedAndApproveRequest(
            input,
            witness,
            AVARequestAllocation.ScopedRequestAuthorities(
                ROLE_SOURCE, creatorAuthority, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
            )
        );
        require(id == nextId && requestAllocation.getRequest(id).allocator == ALLOCATOR_ACTOR, "retry failed");
    }

    function testSecondWitnessPrimaryApprovesWithinGasBudgetAndCompletes() public {
        application =
            new RequestSupportPrimaryApplication(kernel, requestAllocation.recognitionScopeHash(_reviewScope(true)));
        _installPolicy(address(policy));
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[1].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        bytes32 beforeStates = keccak256(
            abi.encode(
                kernel.getRecognisedState(witness[0].recognisedStateId),
                kernel.getRecognisedState(witness[1].recognisedStateId)
            )
        );
        bytes32 beforeWitness = keccak256(abi.encode(requestAllocation.getSupportWitness(id)));
        _expectExecutionRevert(id, input);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        bytes32 allocatorAuthority = _authority(ROLE_ALLOCATOR);
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        requestAllocation.approve(id, ROLE_ALLOCATOR, allocatorAuthority);
        uint256 approvalGas = beforeGas - gasleft();
        emit log_named_uint("second-primary approval call gas", approvalGas);
        beforeGas = gasleft();
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        emit log_named_uint("second-primary consume and complete call gas", beforeGas - gasleft());
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(id);
        require(completed.completed && completed.consumed && completed.allocator == ALLOCATOR_ACTOR, "effect missing");
        require(completed.input.recognisedStateId == witness[1].recognisedStateId, "primary changed");
        require(
            keccak256(
                    abi.encode(
                        kernel.getRecognisedState(witness[0].recognisedStateId),
                        kernel.getRecognisedState(witness[1].recognisedStateId)
                    )
                ) == beforeStates && keccak256(abi.encode(requestAllocation.getSupportWitness(id))) == beforeWitness,
            "source history changed"
        );
        _expectExecutionRevert(id, input);
        require(approvalGas <= 220_000, "second-primary approval exceeds 220k call gas");
    }

    function testEitherSingletonFailsJointSupport() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        for (uint256 i; i < 2; ++i) {
            IAVARequestPolicy.WitnessInput[] memory singleton = new IAVARequestPolicy.WitnessInput[](1);
            singleton[0] = witness[i];
            _expectCreationRevertWithData(
                _input(witness[i].recognisedStateId, false),
                singleton,
                abi.encodeWithSignature("Error(string)", "joint pair required")
            );
        }
    }

    function testDuplicateUnsortedAndExtraIrrelevantWitnessesReject() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        IAVARequestPolicy.WitnessInput[] memory malformed = new IAVARequestPolicy.WitnessInput[](2);
        malformed[0] = witness[0];
        malformed[1] = witness[0];
        _expectCreationRevertWithData(
            input, malformed, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, witness[0].recognisedStateId)
        );
        malformed[0] = witness[1];
        malformed[1] = witness[0];
        _expectCreationRevertWithData(
            input, malformed, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, witness[0].recognisedStateId)
        );
        IAVARequestPolicy.WitnessInput[] memory extra = new IAVARequestPolicy.WitnessInput[](3);
        extra[0] = witness[0];
        extra[1] = witness[1];
        extra[2] = _createScopedState(
            IAVARequestPolicy.RecognitionScope(
                keccak256("irrelevant claim"),
                RequestSupportDomain.TWO_RESPONSE_USE,
                RequestSupportDomain.STANDARD_EVIDENCE
            )
        );
        _expectCreationRevertWithData(input, extra, abi.encodeWithSignature("Error(string)", "joint pair required"));
        require(_createSupported(input, witness) != 0, "valid pair rejected");
    }

    function testEmptyAndAboveMaximumWitnessSetsRejectAtGenericBound() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        _expectCreationRevertWithSelector(
            input, new IAVARequestPolicy.WitnessInput[](0), AVACoreTypes.EmptyValue.selector
        );
        IAVARequestPolicy.WitnessInput[] memory tooMany = new IAVARequestPolicy.WitnessInput[](17);
        for (uint256 i; i < tooMany.length; ++i) {
            tooMany[i] = witness[0];
        }
        _expectCreationRevertWithSelector(input, tooMany, AVACoreTypes.EmptyValue.selector);
        require(requestAllocation.MAX_SUPPORT_WITNESSES() == 16, "unexpected bound");
    }

    function testPrimarySourceMustBeIncludedInExplicitWitness() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        IAVARequestPolicy.WitnessInput memory other = _createScopedState(_completionScope());
        _expectCreationRevert(_input(other.recognisedStateId, false), witness);
    }

    function testForgedScopeAndStaleTransitionRejectWithoutChangingRecognition() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        IAVARequestPolicy.RecognitionScope memory original = _completionScope();
        witness[0].scope.claimHash = keccak256("forged claim");
        _expectCreationRevert(input, witness);
        witness[0].scope = original;
        uint256 oldTransition = witness[1].transitionId;
        _changeState(
            witness[1].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Restored,
            AVACoreTypes.TransitionKind.Restoration
        );
        _expectCreationRevert(input, witness);
        witness[1].transitionId = kernel.getRecognisedStateReference(witness[1].recognisedStateId).lastTransitionId;
        require(witness[1].transitionId != oldTransition, "transition unchanged");
        require(_createSupported(input, witness) != 0, "fresh support rejected");
    }

    function testSameImmutableRecognitionSupportsTwoExplicitlyMatchedBoundedUses() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        require(
            witness[0].scope.useHash != RequestSupportDomain.RELEASE
                && witness[0].scope.useHash != RequestSupportDomain.PRIORITY,
            "test requires selected matching"
        );
        bytes32 beforeWitness = keccak256(abi.encode(witness));
        for (uint256 i; i < 2; ++i) {
            AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, i == 1);
            uint256 id = _createSupported(input, witness);
            _approveRequest(id);
            executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
            require(requestAllocation.getRequest(id).completed, "bounded response failed");
        }
        require(keccak256(abi.encode(witness)) == beforeWitness, "recognition rewritten");
        require(
            kernel.getRecognisedStateReference(witness[0].recognisedStateId).lastTransitionId
                == witness[0].transitionId,
            "recognition transitioned"
        );
    }

    function testEligibilityVariesByRequestRuleWhileGlobalStatusRemainsVested() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(false);
        uint256 review = witness[1].recognisedStateId;
        uint256 transition = witness[1].transitionId;
        require(_createSupported(_input(witness[0].recognisedStateId, false), witness) != 0, "release ineligible");
        _expectCreationRevert(_input(witness[0].recognisedStateId, true), witness);
        require(
            kernel.getRecognisedStateReference(review).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "global enum changed"
        );
        require(kernel.getRecognisedStateReference(review).lastTransitionId == transition, "global history changed");
        witness[1] = _createScopedState(_reviewScope(true));
        require(_createSupported(_input(witness[0].recognisedStateId, true), witness) != 0, "strong review ineligible");
    }

    function testCommittedButInapplicableScopesAndWrongRequestTermsReject() public {
        for (uint256 i; i < 3; ++i) {
            IAVARequestPolicy.RecognitionScope memory scope = _completionScope();
            if (i == 0) scope.claimHash = keccak256("other committed claim");
            if (i == 1) scope.useHash = keccak256("other committed use");
            if (i == 2) scope.burdenHash = RequestSupportDomain.STRONG_EVIDENCE;
            IAVARequestPolicy.WitnessInput[] memory witness = new IAVARequestPolicy.WitnessInput[](2);
            witness[0] = _createScopedState(scope);
            witness[1] = _createScopedState(_reviewScope(true));
            string memory reason = i == 0 ? "claim matching" : (i == 1 ? "bounded use" : "completion burden");
            _expectCreationRevertWithData(
                _input(witness[0].recognisedStateId, false), witness, abi.encodeWithSignature("Error(string)", reason)
            );
        }
        IAVARequestPolicy.WitnessInput[] memory valid = _pair(true);
        for (uint256 i; i < 3; ++i) {
            AVARequestAllocation.RequestInput memory input = _input(valid[0].recognisedStateId, false);
            if (i == 0) input.executor = address(new RequestSupportExecutor());
            if (i == 1) input.burdenHash = RequestSupportDomain.PRIORITY_BURDEN;
            if (i == 2) input.responseClass = keccak256("unselected response");
            string memory reason = i == 0 ? "executor or mode" : (i == 1 ? "request burden" : "response");
            _expectCreationRevertWithData(input, valid, abi.encodeWithSignature("Error(string)", reason));
        }
    }

    function testActorNeutralSupportDoesNotConferActorSpecificDecision() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        uint256 id = _createSupported(_input(witness[0].recognisedStateId, false), witness);
        address otherAllocator = address(0xA2);
        bytes32 otherAuthority = keccak256("other active allocator");
        identityRegistry.assignSubject(
            otherAllocator, requestAppId, ROLE_ALLOCATOR, otherAuthority, "test:other-allocator"
        );
        requestVm.prank(otherAllocator);
        require(requestAllocation.validateCurrentSupport(id) != bytes32(0), "neutral support actor-bound");
        requestVm.prank(otherAllocator);
        requestVm.expectRevert();
        requestAllocation.approve(id, ROLE_ALLOCATOR, otherAuthority);
        require(requestAllocation.getRequest(id).allocator == address(0), "failed decision persisted");
        _approveRequest(id);
        require(requestAllocation.getRequest(id).allocator == ALLOCATOR_ACTOR, "selected actor rejected");
    }

    function testExternalUserCannotBindOrReplaceHelperWitnessContext() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        uint256 id = _createSupported(_input(witness[0].recognisedStateId, false), witness);
        AVARequestSupport helper = requestAllocation.SUPPORT();
        IAVARequestPolicy.RequestContext memory context = helper.requestContext(id);
        bytes32 originalContext = keccak256(abi.encode(context));
        bytes32 originalWitness = keccak256(abi.encode(helper.getWitness(id)));
        address externalUser = address(0xBAD);

        // A canonical-looking new context does not grant the caller custody rights.
        context.requestId = id + 1;
        requestVm.prank(externalUser);
        RequestSupportVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, context.requestId));
        helper.bind(context, witness[0].transitionId, witness);
        RequestSupportVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, context.requestId));
        helper.requestContext(context.requestId);

        // Existing custody cannot be replaced with changed terms or witness input.
        context.requestId = id;
        context.parametersHash = keccak256("forged helper parameters");
        witness[0].scope.claimHash = keccak256("forged helper claim");
        requestVm.prank(externalUser);
        RequestSupportVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        helper.bind(context, witness[0].transitionId, witness);
        require(keccak256(abi.encode(helper.requestContext(id))) == originalContext, "helper context replaced");
        require(keccak256(abi.encode(helper.getWitness(id))) == originalWitness, "helper witness replaced");
        require(requestAllocation.validateCurrentSupport(id) != bytes32(0), "support damaged");
    }

    function testExternalUserCannotInvokeHelperDecisionWithForgedActor() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        uint256 id = _createSupported(_input(witness[0].recognisedStateId, false), witness);
        AVARequestSupport helper = requestAllocation.SUPPORT();
        IAVARequestPolicy.DecisionContext memory decision = IAVARequestPolicy.DecisionContext(
            ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), ALLOCATOR_ACTOR, uint64(block.timestamp)
        );
        requestVm.prank(address(0xBAD));
        RequestSupportVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        helper.validateDecision(id, decision);
        require(requestAllocation.getRequest(id).allocator == address(0), "forged decision persisted");
        _approveRequest(id);
        require(requestAllocation.getRequest(id).allocator == ALLOCATOR_ACTOR, "owner decision rejected");
    }

    function testCurrentAllocationAuthorityRevocationBlocksApprovalAndConsumption() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        authorityMatrix.setPermission(requestAppId, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        _approveRequest(id);
        require(requestAllocation.validateCurrentSupport(id) != bytes32(0), "support became authority");
        authorityMatrix.setPermission(requestAppId, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        _approveRequest(id);
        authorityMatrix.setPermission(requestAppId, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        require(!requestAllocation.getRequest(id).consumed, "revoked consume persisted");
        authorityMatrix.setPermission(requestAppId, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
    }

    function testReplacementAuthorityCannotInheritOldApproval() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 oldId = _createSupported(input, witness);
        _approveRequest(oldId);
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        bytes32 replacement = keccak256("replacement allocator authority");
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, requestAppId, ROLE_ALLOCATOR, replacement, "test:replacement");
        _expectExecutionRevert(oldId, input);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.approve(oldId, ROLE_ALLOCATOR, replacement);
        _refreshSecondary(witness);
        uint256 successor = _createSupported(input, witness);
        _expectExecutionRevert(successor, input);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.approve(successor, ROLE_ALLOCATOR, replacement);
        executor.execute(requestAllocation, successor, input.responseClass, input.parametersHash);
        require(
            requestAllocation.getRequest(oldId).allocatorAuthorityId == _authority(ROLE_ALLOCATOR),
            "old authority replaced"
        );
        require(requestAllocation.getRequest(successor).allocatorAuthorityId == replacement, "fresh authority missing");
    }

    function testSecondaryTransitionBlocksOldRequestAndRestorationNeedsExplicitSuccessorDecision() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 oldId = _createSupported(input, witness);
        _approveRequest(oldId);
        bytes32 oldHash = requestAllocation.supportWitnessHash(oldId);
        uint256 oldSecondaryTransition = witness[1].transitionId;
        _changeState(
            witness[1].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _expectExecutionRevert(oldId, input);
        _changeState(
            witness[1].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Restored,
            AVACoreTypes.TransitionKind.Restoration
        );
        _expectExecutionRevert(oldId, input);
        witness[1].transitionId = kernel.getRecognisedStateReference(witness[1].recognisedStateId).lastTransitionId;
        uint256 successor = _createSupported(input, witness);
        require(requestAllocation.getRequest(successor).supersedesRequestId == oldId, "predecessor missing");
        require(requestAllocation.supersededByRequest(oldId) == successor, "successor missing");
        require(requestAllocation.getRequest(successor).allocator == address(0), "restoration autoapproved");
        _expectExecutionRevert(successor, input);
        _approveRequest(successor);
        executor.execute(requestAllocation, successor, input.responseClass, input.parametersHash);
        require(
            requestAllocation.getSupportWitness(oldId)[1].transitionId == oldSecondaryTransition,
            "old witness overwritten"
        );
        require(
            requestAllocation.supportWitnessHash(oldId) == oldHash && !requestAllocation.getRequest(oldId).consumed,
            "old decision rewritten"
        );
        _expectExecutionRevert(oldId, input);
    }

    function testConsumedMeaningCannotReplayThroughDeadlineBurdenOrFreshRecognition() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        _approveRequest(id);
        executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        input.validUntil++;
        _expectCreationRevertWithData(input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        input.validUntil--;
        input.burdenHash = keccak256("relabelled burden");
        _expectCreationRevertWithData(input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        IAVARequestPolicy.WitnessInput[] memory fresh = _pair(true);
        input = _input(fresh[0].recognisedStateId, false);
        _expectCreationRevertWithData(input, fresh, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        require(requestAllocation.supportedRequestIdByMeaning(_meaning(input)) == id, "consumed meaning replaced");
    }

    function testUnconsumedSuccessorCannotSilentlyExtendExpiryOrReplaceBurden() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 oldId = _createSupported(input, witness);
        _refreshSecondary(witness);
        input.validUntil++;
        _expectCreationRevertWithData(input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, oldId));
        input.validUntil--;
        bytes32 originalBurden = input.burdenHash;
        input.burdenHash = RequestSupportDomain.PRIORITY_BURDEN;
        _expectCreationRevertWithData(input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, oldId));
        input.burdenHash = originalBurden;
        uint256 successor = _createSupported(input, witness);
        require(requestAllocation.getRequest(successor).supersedesRequestId == oldId, "same terms successor missing");
        require(requestAllocation.getRequest(successor).input.validUntil == input.validUntil, "expiry changed");
    }

    function testCancelledScopedRequestNeedsFreshSupportAndAllocationForSuccessor() public {
        _assertTerminalSuccessor(true, false);
    }

    function testExpiredUnapprovedScopedRequestCanReceiveFreshAuthorisedSuccessor() public {
        _assertTerminalSuccessor(false, false);
    }

    function testExpiredApprovedScopedRequestDoesNotTransferItsAllocationToSuccessor() public {
        _assertTerminalSuccessor(false, true);
    }

    function testTerminalSuccessorFreshBurdenRequiresTheReceivingRulesStrongerSupport() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(false);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 oldId = _createSupported(input, witness);
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.cancel(oldId);
        bytes32 oldRecord = keccak256(abi.encode(requestAllocation.getRequest(oldId)));
        bytes32 oldSupport = requestAllocation.supportWitnessHash(oldId);
        input.burdenHash = RequestSupportDomain.RENEWED_RELEASE_BURDEN;
        input.validUntil++;
        _expectCreationRevertWithData(input, witness, abi.encodeWithSignature("Error(string)", "review burden"));
        input.burdenHash = RequestSupportDomain.RELEASE_BURDEN;
        _revokeEvidence(kernel.getRecognisedStateReference(witness[1].recognisedStateId).evidenceReceiptId);
        _expectCreationRevert(input, witness);
        input.burdenHash = RequestSupportDomain.RENEWED_RELEASE_BURDEN;
        IAVARequestPolicy.WitnessInput[] memory freshWitness = _pair(true);
        input.recognisedStateId = freshWitness[0].recognisedStateId;
        uint256 successor = _createSupported(input, freshWitness);
        require(requestAllocation.getRequest(successor).input.burdenHash == RequestSupportDomain.RENEWED_RELEASE_BURDEN);
        require(requestAllocation.getRequest(successor).allocator == address(0), "fresh burden inherited approval");
        _approveRequest(successor);
        executor.execute(requestAllocation, successor, input.responseClass, input.parametersHash);
        require(requestAllocation.getRequest(successor).completed, "fresh burden effect missing");
        require(keccak256(abi.encode(requestAllocation.getRequest(oldId))) == oldRecord, "prior burden rewritten");
        require(requestAllocation.supportWitnessHash(oldId) == oldSupport, "prior support replaced");
    }

    function _assertTerminalSuccessor(bool cancelled, bool approved) private {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 oldId = _createSupported(input, witness);
        if (approved) _approveRequest(oldId);
        _expectCreationRevertWithData(input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, oldId));
        if (cancelled) {
            requestVm.prank(SOURCE_ACTOR);
            requestAllocation.cancel(oldId);
        } else {
            requestVm.warp(input.validUntil);
        }
        bytes32 oldRecord = keccak256(abi.encode(requestAllocation.getRequest(oldId)));
        bytes32 oldSupport = requestAllocation.supportWitnessHash(oldId);
        bytes32 oldWitness = keccak256(abi.encode(requestAllocation.getSupportWitness(oldId)));
        bytes32 sourceHistory = keccak256(abi.encode(kernel.getRecognisedStateReference(input.recognisedStateId)));
        uint256 secondaryTransition = witness[1].transitionId;
        bytes32 occurrenceHistory = keccak256(abi.encode(kernel.getRecognisedStateTransition(secondaryTransition)));
        input.validUntil = uint64(block.timestamp + 2 days);

        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createSupportedRequest(input, witness, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        bytes32 burden = input.burdenHash;
        input.burdenHash = keccak256("invented renewal burden");
        _expectCreationRevert(input, witness);
        input.burdenHash = burden;
        _refreshSecondary(witness);
        uint256 currentTransition = witness[1].transitionId;
        witness[1].transitionId = secondaryTransition;
        _expectCreationRevert(input, witness);
        witness[1].transitionId = currentTransition;
        require(
            requestAllocation.supportedRequestIdByMeaning(_meaning(input)) == oldId, "failed renewal reserved meaning"
        );

        uint256 successor = _createSupported(input, witness);
        AVARequestAllocation.RequestRecord memory fresh = requestAllocation.getRequest(successor);
        require(fresh.supersedesRequestId == oldId && requestAllocation.supersededByRequest(oldId) == successor);
        require(fresh.allocator == address(0) && fresh.approvedAt == 0, "terminal approval inherited");
        require(fresh.input.validUntil == input.validUntil, "fresh terms lost");
        _expectExecutionRevert(successor, input);
        _expectExecutionRevert(oldId, input);
        _approveRequest(successor);
        executor.execute(requestAllocation, successor, input.responseClass, input.parametersHash);
        requestVm.expectRevert();
        executor.execute(requestAllocation, successor, input.responseClass, input.parametersHash);
        input.validUntil++;
        _expectCreationRevertWithData(
            input, witness, abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, successor)
        );
        require(requestAllocation.getRequest(successor).completed, "successor effect missing");
        require(keccak256(abi.encode(requestAllocation.getRequest(oldId))) == oldRecord, "terminal record rewritten");
        require(requestAllocation.supportWitnessHash(oldId) == oldSupport, "terminal support rewritten");
        require(keccak256(abi.encode(requestAllocation.getSupportWitness(oldId))) == oldWitness, "witness rewritten");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateReference(input.recognisedStateId))) == sourceHistory,
            "source recognition rewritten"
        );
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(secondaryTransition))) == occurrenceHistory,
            "source occurrence rewritten"
        );
    }

    function testDefaultGenericPolicyRejectsScopedJointSupport() public {
        _installPolicy(address(0));
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        _expectCreationRevert(_input(witness[0].recognisedStateId, false), witness);
    }

    function testSecondaryEvidenceRevocationAndInactiveSourceBlockLiveSupport() public {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        _approveRequest(id);
        uint256 secondaryEvidence = kernel.getRecognisedStateReference(witness[1].recognisedStateId).evidenceReceiptId;
        _revokeEvidence(secondaryEvidence);
        requestVm.expectRevert();
        requestAllocation.validateCurrentSupport(id);
        _expectExecutionRevert(id, input);
        IAVARequestPolicy.WitnessInput[] memory fresh = _pair(true);
        AVARequestAllocation.RequestInput memory other = _input(fresh[0].recognisedStateId, true);
        uint256 otherId = _createSupported(other, fresh);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        requestVm.expectRevert();
        requestAllocation.validateCurrentSupport(otherId);
        requestVm.expectRevert();
        _approveRequest(otherId);
    }

    function testScopedHistoricalCorrectionSurvivesSupportAuthorityExpiryAndRuleSupersession() public {
        _historicalCorrection(false);
    }

    function testScopedCompletedEffectCorrectionSurvivesSupportAuthorityExpiryAndRuleSupersession() public {
        _historicalCorrection(true);
    }

    function _historicalCorrection(bool completed) private {
        IAVARequestPolicy.WitnessInput[] memory witness = _pair(true);
        AVARequestAllocation.RequestInput memory input = _input(witness[0].recognisedStateId, false);
        uint256 id = _createSupported(input, witness);
        _approveRequest(id);
        if (completed) executor.execute(requestAllocation, id, input.responseClass, input.parametersHash);
        AVARequestAllocation.RequestRecord memory beforeRecord = requestAllocation.getRequest(id);
        bytes32 beforeSupport = requestAllocation.supportWitnessHash(id);
        requestVm.prank(SOURCE_ACTOR);
        uint256 challenge = requestAllocation.fileRequestChallenge(
            id,
            completed ? AVARequestAllocation.ChallengeTarget.Effect : AVARequestAllocation.ChallengeTarget.Allocation,
            beforeRecord.evidenceReceiptId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            keccak256("scoped historical concern")
        );
        _changeState(
            witness[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _installPolicy(address(policy));
        uint256 decisionEvidence = _historicalDecisionEvidence(beforeRecord.packageId);
        _revokeEvidence(beforeRecord.evidenceReceiptId);
        _revokeEvidence(kernel.getRecognisedStateReference(witness[1].recognisedStateId).evidenceReceiptId);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        authorityMatrix.setPermission(requestAppId, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.warp(input.validUntil);
        requestVm.expectRevert();
        requestAllocation.validateCurrentSupport(id);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(
            AVARequestAllocation.ResolutionInput({
                challengeId: challenge,
                expectedPreviousResolutionId: 0,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                decisionEvidenceId: decisionEvidence,
                outcome: completed
                    ? AVARequestAllocation.ResolutionOutcome.Residual
                    : AVARequestAllocation.ResolutionOutcome.Withdrawn,
                reasonHash: keccak256("scoped independent resolution"),
                remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
                finding: _findingInput(true)
            })
        );
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            receipt.outcome
                == (completed
                        ? AVARequestAllocation.ResolutionOutcome.Residual
                        : AVARequestAllocation.ResolutionOutcome.Withdrawn),
            "historical correction blocked"
        );
        require(
            receipt.sourceStatusAtFiling == AVACoreTypes.RecognisedStateStatus.Vested
                && receipt.sourceStatusAtResolution == AVACoreTypes.RecognisedStateStatus.Voided,
            "historical observations missing"
        );
        require(
            requestAllocation.withdrawalResolutionIdByRequest(id) == (completed ? 0 : challenge), "withdrawal identity"
        );
        AVARequestAllocation.RequestRecord memory retained = requestAllocation.getRequest(id);
        require(
            retained.packageId == beforeRecord.packageId && retained.allocator == beforeRecord.allocator
                && retained.recognisedStateTransitionId == beforeRecord.recognisedStateTransitionId,
            "allocation history changed"
        );
        require(
            requestAllocation.supportWitnessHash(id) == beforeSupport && retained.consumed == completed
                && retained.completed == completed && retained.effectHash == beforeRecord.effectHash,
            "support history changed"
        );
    }

    function _installPolicy(address selectedPolicy) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        if (selectedPolicy != address(0)) bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, selectedPolicy);
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                requestAppId,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++ruleVersion,
                keccak256("request.compatibility"),
                "test:scoped-rules"
            ),
            requestPackageId,
            bindings
        );
    }

    function _pair(bool strongReview) private returns (IAVARequestPolicy.WitnessInput[] memory witness) {
        witness = new IAVARequestPolicy.WitnessInput[](2);
        witness[0] = _createScopedState(_completionScope());
        witness[1] = _createScopedState(_reviewScope(strongReview));
    }

    function _completionScope() private pure returns (IAVARequestPolicy.RecognitionScope memory) {
        return IAVARequestPolicy.RecognitionScope(
            RequestSupportDomain.COMPLETION_CLAIM,
            RequestSupportDomain.TWO_RESPONSE_USE,
            RequestSupportDomain.STANDARD_EVIDENCE
        );
    }

    function _reviewScope(bool strong) private pure returns (IAVARequestPolicy.RecognitionScope memory) {
        return IAVARequestPolicy.RecognitionScope(
            RequestSupportDomain.REVIEW_CLAIM,
            RequestSupportDomain.TWO_RESPONSE_USE,
            strong ? RequestSupportDomain.STRONG_EVIDENCE : RequestSupportDomain.STANDARD_EVIDENCE
        );
    }

    function _createScopedState(IAVARequestPolicy.RecognitionScope memory scope)
        private
        returns (IAVARequestPolicy.WitnessInput memory witness)
    {
        bytes32 objectCommitment = keccak256(abi.encode("immutable recognised work", evidenceRegistry.nextEvidenceId()));
        requestVm.startPrank(SOURCE_ACTOR);
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: requestAppId,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: keccak256(abi.encode(objectCommitment, "evidence")),
                evidenceTypeHash: keccak256("scoped support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:scoped-evidence"
            })
        );
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: requestAppId,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: requestObjectTypeKey,
                objectCommitment: objectCommitment,
                parentObjectId: 0,
                subjectId: _authority(ROLE_SOURCE),
                evidenceReceiptId: evidence,
                disclosurePolicyId: requestPolicyId,
                metadataHash: requestAllocation.recognitionScopeHash(scope),
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:scoped-object"
            })
        );
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 stateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: keccak256("scoped formation"),
                reasonURI: "test:scoped-formation"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return
            IAVARequestPolicy.WitnessInput(stateId, kernel.getRecognisedStateReference(stateId).lastTransitionId, scope);
    }

    function _input(uint256 primary, bool priority) private view returns (AVARequestAllocation.RequestInput memory) {
        return AVARequestAllocation.RequestInput(
            primary,
            address(executor),
            priority ? RequestSupportDomain.PRIORITY : RequestSupportDomain.RELEASE,
            PARAMETERS,
            priority ? RequestSupportDomain.PRIORITY_BURDEN : RequestSupportDomain.RELEASE_BURDEN,
            uint64(block.timestamp + 1 days)
        );
    }

    function _createSupported(
        AVARequestAllocation.RequestInput memory input,
        IAVARequestPolicy.WitnessInput[] memory witness
    ) private returns (uint256) {
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.createSupportedRequest(input, witness, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectCreationRevert(
        AVARequestAllocation.RequestInput memory input,
        IAVARequestPolicy.WitnessInput[] memory witness
    ) private {
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createSupportedRequest(input, witness, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectCreationRevertWithSelector(
        AVARequestAllocation.RequestInput memory input,
        IAVARequestPolicy.WitnessInput[] memory witness,
        bytes4 selector
    ) private {
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert(selector);
        requestAllocation.createSupportedRequest(input, witness, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectCreationRevertWithData(
        AVARequestAllocation.RequestInput memory input,
        IAVARequestPolicy.WitnessInput[] memory witness,
        bytes memory revertData
    ) private {
        requestVm.prank(SOURCE_ACTOR);
        RequestSupportVm(address(requestVm)).expectRevert(revertData);
        requestAllocation.createSupportedRequest(input, witness, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectExecutionRevert(uint256 id, AVARequestAllocation.RequestInput memory input) private {
        requestVm.expectRevert();
        requestAllocation.validateExecution(id, input.responseClass, input.parametersHash, input.executor);
    }

    function _meaning(AVARequestAllocation.RequestInput memory input) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(requestAllocation),
                requestAppId,
                input.executor,
                input.responseClass,
                input.parametersHash
            )
        );
    }

    function _refreshSecondary(IAVARequestPolicy.WitnessInput[] memory witness) private {
        _changeState(
            witness[1].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Restored,
            AVACoreTypes.TransitionKind.Restoration
        );
        witness[1].transitionId = kernel.getRecognisedStateReference(witness[1].recognisedStateId).lastTransitionId;
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
                decisionHash: keccak256(abi.encode("scoped source decision", stateId, status)),
                toStatus: status,
                kind: kind,
                reasonHash: keccak256(abi.encode("scoped source reason", stateId, status)),
                reasonURI: "test:scoped-transition"
            })
        );
    }

    function _revokeEvidence(uint256 evidence) private {
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("scoped revocation"),
            "test:scoped-revocation"
        );
    }

    function _historicalDecisionEvidence(uint256 historicalPackage) private returns (uint256) {
        authorityMatrix.setPermission(
            requestAppId, ROLE_VERIFIER, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true
        );
        requestVm.prank(VERIFIER_ACTOR);
        return evidenceRegistry.registerCorrectionEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: requestAppId,
                workflowKey: REQUEST_WORKFLOW,
                packageId: historicalPackage,
                roleKey: ROLE_VERIFIER,
                subjectId: _authority(ROLE_VERIFIER),
                commitment: keccak256("scoped independent decision evidence"),
                evidenceTypeHash: keccak256("scoped correction evidence"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_VERIFIER),
                uri: "test:scoped-correction-evidence"
            }),
            requestPackageId,
            keccak256("scoped historical evidence authority")
        );
    }
}
