// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DecisionSetFixture} from "./DecisionSet.t.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {IAVAProcedurePolicy} from "../src/core/interfaces/IAVAProcedurePolicy.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVAProcedureAdjudication} from "../src/extensions/decisions/AVAProcedureAdjudication.sol";
import {AVABasicProcedurePolicy} from "../src/extensions/decisions/AVABasicProcedurePolicy.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVAPrivacyRegistry} from "../src/extensions/privacy/AVAPrivacyRegistry.sol";
import {AVAEvidenceResourceBinding} from "../src/extensions/privacy/AVAEvidenceResourceBinding.sol";
import {AVABoundConfidentialEvidencePolicy} from "../src/extensions/privacy/AVABoundConfidentialEvidencePolicy.sol";

contract EvidenceAvailabilityCompositionTest is DecisionSetFixture {
    bytes32 private constant CASE_ID = keccak256("availability.composition.case");
    bytes32 private constant MATERIAL = keccak256("availability.composition.material");
    bytes32 private constant RETIRED_RESOURCE = keccak256("availability.composition.retired-resource");
    bytes32 private constant HEALTHY_RESOURCE = keccak256("availability.composition.healthy-resource");
    bytes32 private constant CLOSE = keccak256("availability.composition.close");
    bytes32 private constant CLOSE_ACTION = keccak256("availability.composition.action.close");

    AVAPrivacyRegistry private privacy;
    AVAEvidenceResourceBinding private bindings;
    AVAProcedureAdjudication private adjudicator;
    uint256 private privacyPolicyId;

    function setUp() public override {
        super.setUp();
        privacy = new AVAPrivacyRegistry(authorityMatrix);
        bindings = new AVAEvidenceResourceBinding(privacy, evidenceRegistry);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_POLICY(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_CASE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.REGISTER_RESOURCE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, bindings.BIND_EVIDENCE(), true);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, registry.ACTION_FILE_PROCEDURE_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, registry.ACTION_RESOLVE_PROCEDURE_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        adjudicator = new AVAProcedureAdjudication(registry, new AVABasicProcedurePolicy(APP, REQUEST_WORKFLOW, true));

        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](1);
        rules[0].materialClass = MATERIAL;
        rules[0].readerRole = keccak256("availability.composition.reader");
        rules[0].purpose = keccak256("availability.composition.purpose");
        rules[0].phaseMask = 1;
        rules[0].maxLeaseSeconds = 3600;
        requestVm.startPrank(SOURCE_ACTOR);
        privacyPolicyId = privacy.publishPolicy(APP, ROLE_SOURCE, _authority(ROLE_SOURCE), rules);
        privacy.openCase(CASE_ID, APP, privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();

        AVABoundConfidentialEvidencePolicy boundPolicy =
            new AVABoundConfidentialEvidencePolicy(APP, REQUEST_WORKFLOW, requestPolicyId, bindings, privacyPolicyId);
        IAVADecisionPolicy.Option[] memory options = new IAVADecisionPolicy.Option[](3);
        IAVADecisionPolicy.Option[] memory original = _options(1, true, 0);
        options[0] = original[0];
        options[1] = original[1];
        options[2] =
            IAVADecisionPolicy.Option(CLOSE, IAVADecisionPolicy.Kind.Close, CLOSE_ACTION, PARAMETERS, 0, bytes32(0));
        policy = new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, options);
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(application);
        AVACoreRulePackageRegistry.ModuleBinding[] memory modules = new AVACoreRulePackageRegistry.ModuleBinding[](21);
        for (uint256 i; i < base.length; ++i) {
            modules[i] = base[i];
        }
        modules[4] = _coreBinding(AVACapabilityKeys.EVIDENCE_POLICY, address(boundPolicy));
        modules[5] = _coreBinding(AVACapabilityKeys.DISCLOSURE_POLICY, address(boundPolicy));
        modules[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(bridge));
        modules[19] = _coreBinding(AVACapabilityKeys.DECISION_SET, address(policy));
        modules[20] = _coreBinding(AVACapabilityKeys.PROCEDURE_REVIEW, address(adjudicator));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++version,
                keccak256("request.compatibility"),
                "test:availability-composition-rules"
            ),
            requestPackageId,
            modules
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
    }

    function testRetiredPrivateResourceLeavesHealthySupportAndAuthorisedProcedureAvailable() public {
        IAVADecisionPolicy.Request memory input = _input("private-resource-retirement");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _boundState(scope, RETIRED_RESOURCE);
        pool[1] = _boundState(scope, HEALTHY_RESOURCE);
        uint256 id = _open(input, pool);
        require(registry.getEligibleWitnesses(id).length == 2 && _d(id).length == 2, "initial support and options");
        uint256 retiredEvidence = kernel.getRecognisedStateReference(pool[0].recognisedStateId).evidenceReceiptId;
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 nextExecution = requestAllocation.nextRequestId();

        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(
            evidenceRegistry.getEvidenceReference(retiredEvidence).status == AVACoreTypes.EvidenceStatus.Active,
            "private retirement must leave the Core receipt active"
        );
        IAVARequestPolicy.Witness[] memory eligible = registry.getEligibleWitnesses(id);
        require(
            eligible.length == 1 && eligible[0].recognisedStateId == pool[1].recognisedStateId,
            "retired member must not hide independent healthy support"
        );
        IAVADecisionPolicy.Option[] memory admissible = _d(id);
        require(
            admissible.length == 2 && admissible[0].key == POSITIVE && admissible[1].key == PROCEDURE,
            "healthy positive and authorised procedure must remain available"
        );
        require(
            !authorityMatrix.isAuthorised(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, registry.ACTION_UPDATE_SUPPORT()),
            "procedural actor cannot repair the declared pool"
        );

        uint256 decisionId = _choose(id, PROCEDURE, 0, 0);
        AVADecisionRegistry.DecisionRecord memory chosen = registry.getDecision(decisionId);
        AVADecisionRegistry.AtomicRequest memory afterRequest = registry.getRequest(id);
        require(chosen.witness.length == 0 && chosen.executionRequestId == 0, "procedure must need no witness");
        require(afterRequest.paused && !afterRequest.closed, "seek evidence must pause the pending process");
        require(afterRequest.allocationDecisionId == 0 && afterRequest.supportRevision == 1, "pool stays unchanged");
        require(requestAllocation.nextRequestId() == nextExecution, "procedure must not create execution");
        require(kernel.nextRecognisedStateId() == nextState, "procedure must not create recognition");
    }

    function testCoreNeutralProcedureReviewRecognisesPrivateResourceLoss() public {
        (uint256 id, uint256 target, uint256 challenge, uint256 evidenceId) = _fileBoundProcedure("Core neutral");
        bytes32 beforeRequest = keccak256(abi.encode(registry.getRequest(id)));
        bytes32 beforeDecision = keccak256(abi.encode(registry.getDecision(target)));
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = adjudicator.correctionReviewCaseIdByChallenge(challenge);
        input.expectedTargetVersion = target;
        input.outcome = IAVACorrectionReview.Outcome.EvidenceUnavailable;
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.reasonHash = REASON;
        input.finding = _findingInput(false);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        corrections.review(input);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(evidenceRegistry.getEvidenceReference(evidenceId).status == AVACoreTypes.EvidenceStatus.Active);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 reviewId = corrections.review(input);
        require(corrections.getCase(input.caseId).reviewId == reviewId, "Core neutral review not retained");
        require(
            adjudicator.getResolution(adjudicator.getChallenge(challenge).resolutionId).outcome
                == IAVAProcedurePolicy.Outcome.EvidenceUnavailable,
            "Core review did not neutrally resolve accepted procedure case"
        );
        require(keccak256(abi.encode(registry.getRequest(id))) == beforeRequest, "Core neutral changed controls");
        require(keccak256(abi.encode(registry.getDecision(target))) == beforeDecision, "Core neutral rewrote decision");
        require(registry.procedureDisposition(target) == 0, "Core neutral disposed original procedure");
    }

    function testRetiredPrivacyPolicyAllowsAuthorisedCloseWithoutSupportOrEffect() public {
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, CLOSE_ACTION, true);
        IAVADecisionPolicy.Request memory input = _input("private-policy-retirement");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _boundState(scope, RETIRED_RESOURCE);
        pool[1] = _boundState(scope, HEALTHY_RESOURCE);
        uint256 id = _open(input, pool);
        require(_d(id).length == 3, "initial positive and procedures missing");
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 nextExecution = requestAllocation.nextRequestId();
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivatePolicy(privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(registry.getEligibleWitnesses(id).length == 0, "retired policy retained support");
        IAVADecisionPolicy.Option[] memory admissible = _d(id);
        require(
            admissible.length == 2 && admissible[0].key == PROCEDURE && admissible[1].key == CLOSE,
            "zero support must retain only authorised procedures"
        );
        uint256 decisionId = _choose(id, CLOSE, 0, 0);
        AVADecisionRegistry.DecisionRecord memory decision = registry.getDecision(decisionId);
        AVADecisionRegistry.AtomicRequest memory afterRequest = registry.getRequest(id);
        require(afterRequest.closed && afterRequest.allocationDecisionId == 0, "close did not end pending request");
        require(decision.witness.length == 0 && decision.executionRequestId == 0, "close fabricated support or effect");
        require(afterRequest.supportRevision == 1 && _d(id).length == 0, "close changed support or left options open");
        require(requestAllocation.nextRequestId() == nextExecution, "close created execution");
        require(kernel.nextRecognisedStateId() == nextState, "close created recognition");
    }

    function testUnavailablePrivateCandidateCannotHideTechnicalModuleIdentityFailure() public {
        IAVADecisionPolicy.Request memory input = _input("private-loss-technical-failure");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _boundState(scope, RETIRED_RESOURCE);
        pool[1] = _boundState(scope, HEALTHY_RESOURCE);
        uint256 id = _open(input, pool);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(registry.getEligibleWitnesses(id).length == 1, "known private loss was not an exclusion");
        uint256 nextDecision = registry.nextDecisionId();
        requestVm.etch(address(application), hex"00");
        requestVm.expectRevert();
        registry.getEligibleWitnesses(id);
        requestVm.expectRevert();
        registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, PROCEDURE, 0, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.nextDecisionId() == nextDecision, "technical failure appended a decision");
        require(registry.getRequest(id).lastDecisionId == 0, "technical failure changed request head");
    }

    function testOrdinaryProcedureNeutralResolutionRecognisesPrivateResourceLoss() public {
        (uint256 id, uint256 target, uint256 challenge, uint256 evidenceId) = _fileBoundProcedure("ordinary neutral");
        bytes32 beforeRequest = keccak256(abi.encode(registry.getRequest(id)));
        bytes32 beforeDecision = keccak256(abi.encode(registry.getDecision(target)));
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 nextExecution = requestAllocation.nextRequestId();
        AVAProcedureAdjudication.ResolutionInput memory input = AVAProcedureAdjudication.ResolutionInput(
            challenge,
            target,
            IAVAProcedurePolicy.Outcome.EvidenceUnavailable,
            bytes32(0),
            0,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            REASON,
            _findingInput(false)
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        adjudicator.resolve(input);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(evidenceRegistry.getEvidenceReference(evidenceId).status == AVACoreTypes.EvidenceStatus.Active);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 resolutionId = adjudicator.resolve(input);
        AVAProcedureAdjudication.Resolution memory resolution = adjudicator.getResolution(resolutionId);
        require(adjudicator.getChallenge(challenge).resolutionId == resolutionId, "accepted challenge stayed open");
        require(
            resolution.outcome == IAVAProcedurePolicy.Outcome.EvidenceUnavailable && resolution.decisionEvidenceId == 0
                && resolution.replacementDecisionId == 0,
            "private filing loss did not resolve neutrally"
        );
        require(keccak256(abi.encode(registry.getRequest(id))) == beforeRequest, "neutral resolution changed controls");
        require(
            keccak256(abi.encode(registry.getDecision(target))) == beforeDecision, "neutral resolution rewrote decision"
        );
        require(registry.procedureDisposition(target) == 0, "neutral resolution disposed original procedure");
        require(kernel.nextRecognisedStateId() == nextState, "neutral resolution created recognition");
        require(requestAllocation.nextRequestId() == nextExecution, "neutral resolution created execution");
    }

    function testRequestChallengeNeutralPrivateFilingLossPreservesHealthyApprovedExecution() public {
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_RESOLVE_REQUEST_CHALLENGE(), true);
        IAVADecisionPolicy.Request memory input = _input("request-neutral-private-loss");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](1);
        pool[0] = _boundState(scope, HEALTHY_RESOURCE);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        IAVARequestPolicy.WitnessInput memory filing = _boundState(scope, RETIRED_RESOURCE);
        uint256 filingEvidence = kernel.getRecognisedStateReference(filing.recognisedStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        uint256 challengeId = requestAllocation.fileRequestChallenge(
            executionId,
            AVARequestAllocation.ChallengeTarget.Allocation,
            filingEvidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        AVARequestAllocation.ResolutionInput memory resolution = AVARequestAllocation.ResolutionInput({
            challengeId: challengeId,
            expectedPreviousResolutionId: 0,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: 0,
            outcome: AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable,
            reasonHash: REASON,
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(false)
        });
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(resolution);
        bytes32 beforeDecision = keccak256(abi.encode(registry.getDecision(decisionId)));
        uint256 nextState = kernel.nextRecognisedStateId();
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(evidenceRegistry.getEvidenceReference(filingEvidence).status == AVACoreTypes.EvidenceStatus.Active);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(resolution);
        AVARequestAllocation.RequestChallenge memory challenge = requestAllocation.getRequestChallenge(challengeId);
        require(
            challenge.outcome == AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable
                && challenge.decisionEvidenceId == 0 && challenge.evidenceId == filingEvidence,
            "request challenge did not neutrally record private filing loss"
        );
        require(requestAllocation.withdrawalResolutionIdByRequest(executionId) == 0, "neutral loss withdrew approval");
        require(!requestAllocation.getRequest(executionId).cancelled, "neutral loss cancelled execution");
        require(kernel.nextRecognisedStateId() == nextState, "request neutral created recognition");
        require(
            keccak256(abi.encode(registry.getDecision(decisionId))) == beforeDecision, "neutral loss rewrote decision"
        );
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "neutral filing loss blocked healthy execution");
    }

    function testRetiredAncestorExcludesDescendantWithoutSubstitutingOldExecutionWitness() public {
        IAVADecisionPolicy.Request memory input = _input("private-ancestor-retirement");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput memory ancestor = _boundState(scope, RETIRED_RESOURCE);
        AVACoreTypes.SourceOccurrence[] memory deps = new AVACoreTypes.SourceOccurrence[](1);
        deps[0] = AVACoreTypes.SourceOccurrence(ancestor.recognisedStateId, ancestor.transitionId);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _boundStateWithDependencies(scope, keccak256("availability.composition.descendant"), deps);
        pool[1] = _boundState(scope, HEALTHY_RESOURCE);
        uint256 id = _open(input, pool);
        IAVARequestPolicy.WitnessInput[] memory executionPool = new IAVARequestPolicy.WitnessInput[](1);
        executionPool[0] = pool[0];
        uint256 executionId = _execution(input, executionPool, PARAMETERS);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        AVAGovernanceKernel.RecognisedStateReference memory descendant =
            kernel.getRecognisedStateReference(pool[0].recognisedStateId);
        bytes32 descendantHistory = keccak256(abi.encode(descendant));
        bytes32 decisionHistory = keccak256(abi.encode(registry.getDecision(decisionId)));

        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RETIRED_RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        bindings.requireUsableBinding(descendant.evidenceReceiptId);
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(descendant.evidenceReceiptId, descendant.packageId),
            "descendant own evidence must remain available"
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(descendant.governedObjectId), "ancestor loss ignored");
        IAVARequestPolicy.Witness[] memory eligible = registry.getEligibleWitnesses(id);
        require(
            eligible.length == 1 && eligible[0].recognisedStateId == pool[1].recognisedStateId,
            "independent alternative must survive ancestor retirement"
        );
        IAVADecisionPolicy.Option[] memory admissible = _d(id);
        require(admissible.length == 1 && admissible[0].key == PROCEDURE, "authorised procedure lost");
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.expectRevert();
        support.resolve(executionId);
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(!requestAllocation.getRequest(executionId).consumed, "old approval executed with substitute support");
        require(requestAllocation.getRequest(executionId).allocator == ALLOCATOR_ACTOR, "old approval erased");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateReference(descendant.id))) == descendantHistory,
            "ancestor retirement rewrote descendant history"
        );
        require(
            kernel.DEPENDENCIES().getDependencies(descendant.governedObjectId)[0].transitionId == ancestor.transitionId,
            "ancestor occurrence pin changed"
        );
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == decisionHistory, "old decision rewritten");
    }

    function _fileBoundProcedure(bytes32 requestHash)
        private
        returns (uint256 id, uint256 target, uint256 challenge, uint256 evidenceId)
    {
        IAVADecisionPolicy.Request memory input = _input(requestHash);
        IAVARequestPolicy.WitnessInput memory filing = _boundState(
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash),
            RETIRED_RESOURCE
        );
        evidenceId = kernel.getRecognisedStateReference(filing.recognisedStateId).evidenceReceiptId;
        id = _open(input, new IAVARequestPolicy.WitnessInput[](0));
        target = _choose(id, PROCEDURE, 0, 0);
        requestVm.prank(SOURCE_ACTOR);
        challenge = adjudicator.file(target, evidenceId, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON);
    }

    function _boundState(IAVARequestPolicy.RecognitionScope memory scope, bytes32 resourceId)
        private
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        return _boundStateWithDependencies(scope, resourceId, new AVACoreTypes.SourceOccurrence[](0));
    }

    function _boundStateWithDependencies(
        IAVARequestPolicy.RecognitionScope memory scope,
        bytes32 resourceId,
        AVACoreTypes.SourceOccurrence[] memory deps
    ) private returns (IAVARequestPolicy.WitnessInput memory) {
        bytes32 digest = keccak256(abi.encode("encrypted envelope", resourceId));
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.registerResource(resourceId, CASE_ID, MATERIAL, digest, ROLE_SOURCE, _authority(ROLE_SOURCE));
        uint256 evidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: digest,
                evidenceTypeHash: bindings.SHA256_ENCRYPTED_ENVELOPE(),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: bindings.uriFor(resourceId)
            })
        );
        bindings.bindEvidence(evidenceId, resourceId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        AVAGovernanceKernel.GovernedObjectInput memory objectInput = AVAGovernanceKernel.GovernedObjectInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            roleKey: ROLE_SOURCE,
            objectTypeKey: OBJECT,
            objectCommitment: digest,
            parentObjectId: 0,
            subjectId: _authority(ROLE_SOURCE),
            evidenceReceiptId: evidenceId,
            disclosurePolicyId: requestPolicyId,
            metadataHash: requestAllocation.recognitionScopeHash(scope),
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:availability-composition-object"
        });
        uint256 objectId = deps.length == 0
            ? kernel.registerGovernedObject(objectInput)
            : kernel.registerGovernedObjectWithDependencies(objectInput, deps);
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 stateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: REASON,
                reasonURI: "test:availability-composition-recognition"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return
            IAVARequestPolicy.WitnessInput(stateId, kernel.getRecognisedStateReference(stateId).lastTransitionId, scope);
    }
}
