// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARecognisedDecisionPolicy} from "../src/extensions/decisions/AVARecognisedDecisionPolicy.sol";
import {AVAResolvedDecisionPolicy} from "../src/extensions/decisions/AVAResolvedDecisionPolicy.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

contract DecisionExecutor {
    function execute(AVARequestAllocation requests, uint256 id, bytes32 response, bytes32 parameters) external {
        requests.consume(id, response, parameters, msg.sender);
        requests.complete(id, keccak256(abi.encode("decision effect", id)));
    }
}

contract DecisionTransitionRequester is RuleModuleIdentity {
    function change(AVAGovernanceKernel kernel, AVAGovernanceKernel.SourceBoundTransitionInput calldata input)
        external
    {
        kernel.requestSourceBoundTransition(input);
    }
}

contract JointDecisionPolicy is AVAFiniteDecisionPolicy {
    constructor(bytes32 app, bytes32 workflow, Option[] memory options)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {}

    function witnessFor(Request calldata, Option calldata, IAVARequestPolicy.Witness[] calldata eligible)
        external
        pure
        override
        returns (uint256[] memory indices)
    {
        // Explicitly non-monotone domain: the declared evidence must be exactly this pair.
        if (eligible.length != 2) return new uint256[](0);
        indices = new uint256[](2);
        indices[1] = 1;
    }
}

contract BadResolverDecisionPolicy is AVAFiniteDecisionPolicy {
    uint256 private immutable mode;

    constructor(bytes32 app, bytes32 workflow, Option[] memory options, uint256 mode_)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {
        mode = mode_;
    }

    function witnessFor(Request calldata, Option calldata, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        override
        returns (uint256[] memory indices)
    {
        require(mode != 2, "technical resolver failure");
        indices = new uint256[](mode == 1 ? 2 : 1);
        if (mode == 0) indices[0] = eligible.length;
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(CONFIGURATION_HASH, mode));
    }
}

contract CapacityDecisionPolicy is AVAFiniteDecisionPolicy {
    AVADecisionRegistry private immutable registry;

    constructor(bytes32 app, bytes32 workflow, Option[] memory options, AVADecisionRegistry registry_)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {
        registry = registry_;
    }

    function allocationAllowed(Request calldata, Process calldata process, Actor calldata, Option calldata option)
        external
        view
        override
        returns (bool)
    {
        if (option.kind != Kind.Substantive) return true;
        for (uint256 i = 1; i < registry.nextDecisionId(); ++i) {
            AVADecisionRegistry.DecisionRecord memory selected = registry.getDecision(i);
            if (selected.option.kind == Kind.Substantive && selected.id != process.allocationDecisionId) return false;
        }
        return true;
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(CONFIGURATION_HASH, registry));
    }
}

abstract contract DecisionSetFixture is RequestAllocationFixture {
    bytes32 internal constant APP = keccak256("decision.test.app");
    bytes32 internal constant OBJECT = keccak256("decision.test.object");
    bytes32 internal constant RESPONSE = keccak256("decision.test.response");
    bytes32 internal constant BURDEN = keccak256("decision.test.burden");
    bytes32 internal constant POSITIVE = keccak256("decision.test.positive");
    bytes32 internal constant ALTERNATIVE = keccak256("decision.test.alternative");
    bytes32 internal constant PROCEDURE = keccak256("decision.test.seek-evidence");
    bytes32 internal constant PROCEDURE_ACTION = keccak256("decision.test.action.seek-evidence");
    bytes32 internal constant PARAMETERS = keccak256("decision.test.parameters");
    bytes32 internal constant PARAMETERS_B = keccak256("decision.test.parameters.alternative");
    bytes32 internal constant CONDITIONS = keccak256("decision.test.condition");
    bytes32 internal constant REASON = keccak256("decision.test.reason");

    AVADecisionRegistry internal registry;
    AVAFiniteDecisionPolicy internal policy;
    AVARecognisedDecisionPolicy internal bridge;
    M14PermissiveApplicationModule internal application;
    DecisionExecutor internal executor;
    DecisionTransitionRequester internal transitionRequester;
    uint64 internal version = 1;

    function setUp() public virtual {
        application = new M14PermissiveApplicationModule(APP);
        _setUpRequestAllocation(APP, application, OBJECT);
        registry = new AVADecisionRegistry(kernel, requestAllocation);
        executor = new DecisionExecutor();
        bridge = new AVAResolvedDecisionPolicy(registry);
        transitionRequester = new DecisionTransitionRequester();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, registry.ACTION_OPEN_REQUEST(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, registry.ACTION_UPDATE_SUPPORT(), true);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
    }

    function _install(AVAFiniteDecisionPolicy selected) internal {
        policy = selected;
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(application);
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = new AVACoreRulePackageRegistry.ModuleBinding[](20);
        for (uint256 i; i < base.length; ++i) {
            bindings[i] = base[i];
        }
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(bridge));
        bindings[19] = _coreBinding(AVACapabilityKeys.DECISION_SET, address(selected));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++version,
                keccak256("request.compatibility"),
                "test:decision-rules"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
    }

    function _options(uint256 positives, bool procedure, uint64 notBefore)
        internal
        pure
        returns (IAVADecisionPolicy.Option[] memory options)
    {
        options = new IAVADecisionPolicy.Option[](positives + (procedure ? 1 : 0));
        if (positives > 0) {
            options[0] = IAVADecisionPolicy.Option(
                POSITIVE,
                IAVADecisionPolicy.Kind.Substantive,
                AVACoreTypes.ACTION_RECORD_ALLOCATION,
                PARAMETERS,
                0,
                bytes32(0)
            );
        }
        if (positives > 1) {
            options[1] = IAVADecisionPolicy.Option(
                ALTERNATIVE,
                IAVADecisionPolicy.Kind.Substantive,
                AVACoreTypes.ACTION_RECORD_ALLOCATION,
                PARAMETERS_B,
                notBefore,
                CONDITIONS
            );
        }
        if (procedure) {
            options[positives] = IAVADecisionPolicy.Option(
                PROCEDURE,
                IAVADecisionPolicy.Kind.SeekEvidence,
                PROCEDURE_ACTION,
                keccak256("procedure parameters"),
                0,
                bytes32(0)
            );
        }
    }

    function _input(bytes32 requestHash) internal view returns (IAVADecisionPolicy.Request memory) {
        return IAVADecisionPolicy.Request(
            APP,
            REQUEST_WORKFLOW,
            requestPackageId,
            requestHash,
            address(executor),
            RESPONSE,
            BURDEN,
            uint64(block.timestamp + 1 days)
        );
    }

    function _pool(IAVADecisionPolicy.Request memory input, uint256 size)
        internal
        returns (IAVARequestPolicy.WitnessInput[] memory pool)
    {
        pool = new IAVARequestPolicy.WitnessInput[](size);
        for (uint256 i; i < size; ++i) {
            pool[i] = _scopedState(
                IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash)
            );
        }
    }

    function _scopedState(IAVARequestPolicy.RecognitionScope memory scope)
        internal
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        requestVm.startPrank(SOURCE_ACTOR);
        bytes32 commitment = keccak256(abi.encode("declared evidence", evidenceRegistry.nextEvidenceId()));
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: commitment,
                evidenceTypeHash: keccak256("decision witness"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:decision-evidence"
            })
        );
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: OBJECT,
                objectCommitment: commitment,
                parentObjectId: 0,
                subjectId: _authority(ROLE_SOURCE),
                evidenceReceiptId: evidence,
                disclosurePolicyId: requestPolicyId,
                metadataHash: requestAllocation.recognitionScopeHash(scope),
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:decision-object"
            })
        );
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 state = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: REASON,
                reasonURI: "test:decision-recognition"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return IAVARequestPolicy.WitnessInput(state, kernel.getRecognisedStateReference(state).lastTransitionId, scope);
    }

    function _open(IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool)
        internal
        returns (uint256)
    {
        requestVm.prank(SOURCE_ACTOR);
        return registry.openRequest(input, pool, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectOpenRevert(IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool)
        internal
    {
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        registry.openRequest(input, pool, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _d(uint256 id) internal view returns (IAVADecisionPolicy.Option[] memory) {
        return registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function _choose(uint256 id, bytes32 key, uint256 executionId, uint256 previous) internal returns (uint256) {
        requestVm.prank(ALLOCATOR_ACTOR);
        return registry.choose(id, key, executionId, previous, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
    }

    function _execution(
        IAVADecisionPolicy.Request memory input,
        IAVARequestPolicy.WitnessInput[] memory pool,
        bytes32 parameters
    ) internal returns (uint256) {
        uint256 id = registry.requestIdByHash(keccak256(abi.encode(input.appId, input.workflowKey, input.requestHash)));
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.createDecisionRequest(
            id, _executionInput(input, pool, parameters), pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
    }

    function _executionInput(
        IAVADecisionPolicy.Request memory input,
        IAVARequestPolicy.WitnessInput[] memory pool,
        bytes32 parameters
    ) internal pure returns (AVARequestAllocation.RequestInput memory) {
        return AVARequestAllocation.RequestInput(
            pool[0].recognisedStateId,
            input.executor,
            input.responseClass,
            parameters,
            input.burdenHash,
            input.validUntil
        );
    }

    function _change(uint256 stateId, AVACoreTypes.RecognisedStateStatus status, AVACoreTypes.TransitionKind kind)
        internal
    {
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(stateId);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
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
                actionKey: kind == AVACoreTypes.TransitionKind.Restoration
                    ? AVACoreTypes.ACTION_APPLY_RESTORATION
                    : AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                decisionHash: keccak256(abi.encode(stateId, status)),
                toStatus: status,
                kind: kind,
                reasonHash: REASON,
                reasonURI: "test:decision-transition"
            })
        );
    }
}

contract DecisionSetTest is DecisionSetFixture {
    function testUnsupportedRequestExistsAndEmptyDDoesNotSelectOrRecognise() public {
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 id = _open(_input("unsupported"), new IAVARequestPolicy.WitnessInput[](0));
        require(_d(id).length == 0, "unsupported positive admitted");
        require(registry.getRequest(id).lastDecisionId == 0, "query selected");
        require(kernel.nextRecognisedStateId() == nextState, "intake fabricated recognition");
        require(registry.getRequest(id).supportRevision == 1, "empty declaration missing");
    }

    function testSingletonAndMultipleConcreteOptionsRemainComplete() public {
        IAVADecisionPolicy.Request memory input = _input("one");
        uint256 id = _open(input, _pool(input, 1));
        IAVADecisionPolicy.Option[] memory result = _d(id);
        require(result.length == 1 && result[0].key == POSITIVE, "singleton lost");
        _install(
            new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(2, true, uint64(block.timestamp + 1 hours)))
        );
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        input = _input("multiple");
        id = _open(input, _pool(input, 1));
        result = _d(id);
        require(result.length == 3, "full set truncated");
        require(
            result[0].parametersHash == PARAMETERS && result[1].parametersHash == PARAMETERS_B, "concrete parameters"
        );
        require(
            result[1].notBefore == block.timestamp + 1 hours && result[1].conditionsHash == CONDITIONS,
            "conditional fields"
        );
        require(registry.getRequest(id).lastDecisionId == 0, "evaluation changed state");
    }

    function testUnsupportedProceduralChoiceRequiresItsExpressAuthorityAndHasNoAdverseEffect() public {
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, true, 0)));
        uint256 id = _open(_input("procedure"), new IAVARequestPolicy.WitnessInput[](0));
        require(_d(id).length == 0, "procedural authority invented");
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        require(_d(id).length == 1 && _d(id)[0].key == PROCEDURE, "authorised procedure missing");
        uint256 decisionId = _choose(id, PROCEDURE, 0, 0);
        AVADecisionRegistry.AtomicRequest memory afterRequest = registry.getRequest(id);
        AVADecisionRegistry.DecisionRecord memory chosen = registry.getDecision(decisionId);
        require(
            afterRequest.paused && !afterRequest.closed && afterRequest.allocationDecisionId == 0,
            "seek evidence must pause only the pending process"
        );
        require(chosen.witness.length == 0 && chosen.executionRequestId == 0, "procedure needs support");
        require(chosen.reasonHash == REASON && chosen.supportRevision == 1, "decision provenance");
    }

    function testCanonicalAuthorityRevocationAndReplacementImmediatelyChangeD() public {
        IAVADecisionPolicy.Request memory input = _input("authority");
        uint256 id = _open(input, _pool(input, 1));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        require(_d(id).length == 0, "revoked permission admitted");
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        require(_d(id).length == 0, "inactive actor admitted");
        bytes32 replacement = keccak256("replacement allocator subject");
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, replacement, "test:replacement");
        require(_d(id).length == 0, "old authority alias admitted");
        require(
            registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, replacement).length == 1,
            "new canonical missing"
        );
    }

    function testEvidenceAndSourceSubjectLossExcludeKnownPoolMembers() public {
        IAVADecisionPolicy.Request memory input = _input("evidence");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 evidence = kernel.getRecognisedStateReference(pool[0].recognisedStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            REASON,
            "test:revoke"
        );
        require(
            _d(id).length == 0 && registry.getEligibleWitnesses(id).length == 0, "revoked evidence remained eligible"
        );
        input = _input("source subject");
        id = _open(input, _pool(input, 1));
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        require(_d(id).length == 0, "inactive source remained eligible");
    }

    function testPinnedTransitionLossAndExplicitRevisionRetainHistory() public {
        IAVADecisionPolicy.Request memory input = _input("transition");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        bytes32 oldHash = registry.getSupportRevision(id, 1).revisionHash;
        _change(
            pool[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(_d(id).length == 0, "voided occurrence admitted");
        _change(
            pool[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Restored,
            AVACoreTypes.TransitionKind.Restoration
        );
        require(_d(id).length == 0, "new transition silently repinned");
        pool[0].transitionId = kernel.getRecognisedStateReference(pool[0].recognisedStateId).lastTransitionId;
        requestVm.prank(SOURCE_ACTOR);
        registry.updateSupport(id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(_d(id).length == 1, "authorised revision not used");
        AVADecisionRegistry.SupportRevision memory second = registry.getSupportRevision(id, 2);
        require(
            second.previousHash == oldHash && registry.getSupportRevision(id, 1).revisionHash == oldHash,
            "history overwritten"
        );
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        registry.updateSupport(id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function testPoolAdmissionRejectsUnknownUncommittedUnsortedAndOversizedReferences() public {
        IAVADecisionPolicy.Request memory input = _input("bad pool");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 2);
        IAVARequestPolicy.WitnessInput memory first = pool[0];
        pool[0] = pool[1];
        pool[1] = first;
        _expectOpenRevert(input, pool);
        pool[0] = first;
        pool[1] = first;
        _expectOpenRevert(input, pool);
        pool = _pool(input, 1);
        pool[0].scope.claimHash = keccak256("uncommitted scope");
        _expectOpenRevert(input, pool);
        pool[0].recognisedStateId = type(uint256).max;
        _expectOpenRevert(input, pool);
        _expectOpenRevert(input, new IAVARequestPolicy.WitnessInput[](17));
    }

    function testIntakeRejectsDuplicateHashHistoricalPackageAndExpiredRequest() public {
        IAVADecisionPolicy.Request memory input = _input("unique");
        _open(input, new IAVARequestPolicy.WitnessInput[](0));
        _expectOpenRevert(input, new IAVARequestPolicy.WitnessInput[](0));
        uint256 historical = requestPackageId;
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        input = _input("historical intake");
        input.packageId = historical;
        _expectOpenRevert(input, new IAVARequestPolicy.WitnessInput[](0));
        input = _input("expired");
        input.validUntil = uint64(block.timestamp);
        _expectOpenRevert(input, new IAVARequestPolicy.WitnessInput[](0));
    }

    function testMalformedCatalogueRevertsInsteadOfReturningPartialD() public {
        IAVADecisionPolicy.Option[] memory options = _options(2, false, 0);
        options[1].key = options[0].key;
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, options));
        uint256 id = _open(_input("bad catalogue"), new IAVARequestPolicy.WitnessInput[](0));
        requestVm.expectRevert();
        registry.getAdmissibleDecisions(id, address(0), bytes32(0), bytes32(0));
        options = _options(1, false, 0);
        options[0].actionKey = PROCEDURE_ACTION;
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, options));
        id = _open(_input("wrong positive action"), new IAVARequestPolicy.WitnessInput[](0));
        requestVm.expectRevert();
        registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testOutOfRangeDuplicateAndTechnicalResolverFailuresPropagate() public {
        for (uint256 mode; mode < 3; ++mode) {
            _install(new BadResolverDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0), mode));
            IAVADecisionPolicy.Request memory input = _input(keccak256(abi.encode("resolver", mode)));
            uint256 id = _open(input, _pool(input, 1));
            requestVm.expectRevert();
            registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        }
    }

    function testPackageIdentityDriftPropagatesEvenForUnsupportedActor() public {
        uint256 id = _open(_input("identity drift"), new IAVARequestPolicy.WitnessInput[](0));
        requestVm.etch(address(policy), hex"60006000fd");
        requestVm.expectRevert();
        registry.getAdmissibleDecisions(id, address(0), bytes32(0), bytes32(0));
    }

    function testJointNonMonotoneWitnessUsesConcreteSubsetAndDeclaredUniverse() public {
        _install(new JointDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        IAVADecisionPolicy.Request memory input = _input("joint");
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _scopedState(IAVARequestPolicy.RecognitionScope(keccak256("joint claim one"), RESPONSE, BURDEN));
        pool[1] = _scopedState(IAVARequestPolicy.RecognitionScope(keccak256("joint claim two"), RESPONSE, BURDEN));
        uint256 id = _open(input, pool);
        require(_d(id).length == 1, "joint witness lost");
        uint256 executionId = _execution(input, pool, PARAMETERS);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(registry.getDecision(decisionId).witness.length == 2, "joint subset not retained");
        input = _input("nonmonotone");
        id = _open(input, _pool(input, 3));
        require(_d(id).length == 0, "monotonicity incorrectly assumed");
    }

    function testExecutionUsesExactPolicySubsetRatherThanWholeDeclaredPool() public {
        IAVADecisionPolicy.Request memory input = _input("concrete subset");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 2);
        uint256 id = _open(input, pool);
        require(registry.getEligibleWitnesses(id).length == 2 && _d(id).length == 1, "declared universe");
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createDecisionRequest(
            id, _executionInput(input, pool, PARAMETERS), pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        IAVARequestPolicy.WitnessInput[] memory subset = new IAVARequestPolicy.WitnessInput[](1);
        subset[0] = pool[0];
        uint256 executionId = _execution(input, subset, PARAMETERS);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(registry.getDecision(decisionId).witness.length == 1, "whole pool stored as witness");
    }

    function testExplicitChoiceBindsExecutionAndCannotBeReplayed() public {
        IAVADecisionPolicy.Request memory input = _input("execution");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        requestVm.expectRevert();
        requestAllocation.validateExecution(executionId, RESPONSE, PARAMETERS, address(executor));
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        AVADecisionRegistry.DecisionRecord memory chosen = registry.getDecision(decisionId);
        require(
            chosen.actor == ALLOCATOR_ACTOR && chosen.authorityId == _authority(ROLE_ALLOCATOR), "actor substituted"
        );
        require(chosen.witness.length == 1 && chosen.executionRequestId == executionId, "selection binding");
        require(requestAllocation.getRequest(executionId).allocator == ALLOCATOR_ACTOR, "bridge allocator");
        require(_d(id).length == 0, "second positive allocation admitted");
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "real execution failed");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
    }

    function testForeignCreatorCannotReserveExecutionMeaning() public {
        _assertForeignCreatorCannotReserveExecutionMeaning(false);
    }

    function testForeignCreatorCannotReserveExecutionMeaningForPackage() public {
        _assertForeignCreatorCannotReserveExecutionMeaning(true);
    }

    function _assertForeignCreatorCannotReserveExecutionMeaning(bool forPackage) private {
        IAVADecisionPolicy.Request memory input = _input("creator reservation");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        AVARequestAllocation.RequestInput memory executionInput = _executionInput(input, pool, PARAMETERS);
        uint256 nextExecutionId = requestAllocation.nextRequestId();
        uint256 nextDecisionId = registry.nextDecisionId();
        uint256 nextGenericId = registry.nextRequestId();
        uint256 nextTransitionId = kernel.nextTransitionId();
        bytes32 requestBefore = keccak256(abi.encode(registry.getRequest(id)));
        bytes32 supportBefore = keccak256(abi.encode(registry.getSupportRevision(id, 1)));
        bytes32 sourceBefore = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));
        bytes32 occurrenceBefore = keccak256(abi.encode(kernel.getRecognisedStateTransition(pool[0].transitionId)));
        bytes32 meaning = keccak256(abi.encode(block.chainid, requestAllocation, APP, executor, RESPONSE, PARAMETERS));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_CREATE_REQUEST(), true);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        if (forPackage) {
            requestAllocation.createDecisionRequestForPackage(
                id, requestPackageId, executionInput, pool, ROLE_VERIFIER, _authority(ROLE_VERIFIER)
            );
        } else {
            requestAllocation.createDecisionRequest(id, executionInput, pool, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
        }
        require(requestAllocation.nextRequestId() == nextExecutionId, "failed creation advanced execution ID");
        require(registry.nextRequestId() == nextGenericId, "failed creation advanced generic ID");
        require(registry.nextDecisionId() == nextDecisionId, "failed creation advanced decision ID");
        require(requestAllocation.supportedRequestIdByMeaning(meaning) == 0, "foreign meaning reserved");
        require(requestAllocation.consumedRequestIdByMeaning(meaning) == 0, "foreign meaning consumed");
        require(requestAllocation.decisionRequestIdByExecution(nextExecutionId) == 0, "foreign request bound");
        require(!requestAllocation.scopedSupportByRequest(nextExecutionId), "foreign support marked");
        require(requestAllocation.supportWitnessHash(nextExecutionId) == bytes32(0), "foreign support retained");
        requestVm.expectRevert();
        requestAllocation.getRequest(nextExecutionId);
        require(keccak256(abi.encode(registry.getRequest(id))) == requestBefore, "foreign creation changed request");
        require(
            keccak256(abi.encode(registry.getSupportRevision(id, 1))) == supportBefore,
            "foreign creation changed support history"
        );
        require(_d(id).length == 1, "foreign creation blocked legitimate choice");

        requestVm.prank(SOURCE_ACTOR);
        uint256 executionId;
        if (forPackage) {
            executionId = requestAllocation.createDecisionRequestForPackage(
                id, requestPackageId, executionInput, pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
            );
        } else {
            executionId =
                requestAllocation.createDecisionRequest(id, executionInput, pool, ROLE_SOURCE, _authority(ROLE_SOURCE));
        }
        require(executionId == nextExecutionId, "legitimate creator lost execution ID");
        require(requestAllocation.getRequest(executionId).allocator == address(0), "creation allocated execution");
        require(
            keccak256(abi.encode(requestAllocation.getSupportWitness(executionId))) == keccak256(abi.encode(pool)),
            "source occurrence changed"
        );
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(registry.getDecision(decisionId).actor == ALLOCATOR_ACTOR, "selection actor changed");
        require(requestAllocation.getRequest(executionId).creator == SOURCE_ACTOR, "creator changed");
        require(requestAllocation.getRequest(executionId).allocator == ALLOCATOR_ACTOR, "separate allocation lost");
        bytes32 chosenBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        bytes32 selectedRequestBefore = keccak256(abi.encode(registry.getRequest(id)));
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(completed.consumed && completed.completed, "legitimate execution incomplete");
        require(completed.effectHash == keccak256(abi.encode("decision effect", executionId)), "effect lost");
        require(requestAllocation.consumedRequestIdByMeaning(meaning) == executionId, "meaning not consumed");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createDecisionRequest(id, executionInput, pool, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed)),
            "effect history changed"
        );
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == chosenBefore, "decision history changed");
        require(keccak256(abi.encode(registry.getRequest(id))) == selectedRequestBefore, "selection history changed");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == sourceBefore,
            "recognition changed"
        );
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(pool[0].transitionId))) == occurrenceBefore,
            "source history changed"
        );
        require(kernel.nextTransitionId() == nextTransitionId, "execution created recognition history");
    }

    function testFutureConditionalAllocationApprovesInAdvanceAndGatesConsume() public {
        uint64 notBefore = uint64(block.timestamp + 1 hours);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(2, false, notBefore)));
        IAVADecisionPolicy.Request memory input = _input("conditional");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS_B);
        _choose(id, ALTERNATIVE, executionId, 0);
        require(requestAllocation.getRequest(executionId).allocator == ALLOCATOR_ACTOR, "advance allocation blocked");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS_B);
        requestVm.warp(notBefore);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS_B);
        require(requestAllocation.getRequest(executionId).completed, "conditional consume not enabled");
    }

    function testTimingAndConditionsOnlyVariantsRemainDistinctAndSelectedTimingBinds() public {
        uint64 notBefore = uint64(block.timestamp + 1 hours);
        IAVADecisionPolicy.Option[] memory options = _options(2, false, notBefore);
        options[1].parametersHash = PARAMETERS;
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, options));
        IAVADecisionPolicy.Request memory input = _input("same parameters variants");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        IAVADecisionPolicy.Option[] memory result = _d(id);
        require(result.length == 2, "timing variant removed");
        require(result[0].parametersHash == result[1].parametersHash, "parameters unexpectedly differ");
        require(result[0].notBefore == 0 && result[1].notBefore == notBefore, "timing collapsed");
        require(result[1].conditionsHash == CONDITIONS, "conditions collapsed");
        uint256 executionId = _execution(input, pool, PARAMETERS);
        uint256 decisionId = _choose(id, ALTERNATIVE, executionId, 0);
        require(registry.getDecision(decisionId).option.key == ALTERNATIVE, "selected variant replaced");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        requestVm.warp(notBefore);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "selected timing not enabled");
    }

    function testCurrentAuthorityAndWitnessAreRecheckedAfterChoice() public {
        IAVADecisionPolicy.Request memory input = _input("recheck");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        _choose(id, POSITIVE, executionId, 0);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        _change(
            pool[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(!requestAllocation.getRequest(executionId).consumed, "failed consume mutated state");
    }

    function testChoiceCASReasonAndCreatorBindingFailAtomically() public {
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, true, 0)));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        IAVADecisionPolicy.Request memory input = _input("cas");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 proceduralId = _choose(id, PROCEDURE, 0, 0);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, POSITIVE, 0, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, PROCEDURE, 0, proceduralId, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), bytes32(0));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_CREATE_REQUEST(), true);
        uint256 nextExecutionId = requestAllocation.nextRequestId();
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createDecisionRequest(
            id, _executionInput(input, pool, PARAMETERS), pool, ROLE_VERIFIER, _authority(ROLE_VERIFIER)
        );
        require(registry.getRequest(id).lastDecisionId == proceduralId, "failed choice changed history");
        require(requestAllocation.nextRequestId() == nextExecutionId, "foreign creation advanced execution ID");
        require(registry.nextDecisionId() == proceduralId + 1, "failed choice advanced decision ID");
    }

    function testCrossRequestCapacityRuleAffectsFullD() public {
        _install(new CapacityDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0), registry));
        IAVADecisionPolicy.Request memory first = _input("capacity one");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(first, 1);
        uint256 id = _open(first, pool);
        IAVADecisionPolicy.Request memory second = _input("capacity two");
        uint256 otherId = _open(second, _pool(second, 1));
        require(_d(id).length == 1 && _d(otherId).length == 1, "initial capacity");
        _choose(id, POSITIVE, _execution(first, pool, PARAMETERS), 0);
        require(_d(otherId).length == 0, "capacity interaction ignored");
    }

    function testMutableRecordsDoNotChangeRegistryIdentityOrHistoricalPackageValidity() public {
        bytes32 beforeIdentity = registry.moduleIdentityHash();
        IAVADecisionPolicy.Request memory input = _input("stable module identity");
        uint256 id = _open(input, _pool(input, 1));
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        require(_d(id).length == 1, "historical rule lost after supersession");
        require(registry.moduleIdentityHash() == beforeIdentity, "mutable records in module identity");
    }
}
