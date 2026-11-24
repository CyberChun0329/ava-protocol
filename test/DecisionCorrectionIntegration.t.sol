// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DecisionSetFixture} from "./DecisionSet.t.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARequestAllocation, AVARequestCorrectionActions} from "../src/extensions/requests/AVARequestAllocation.sol";

contract DecisionRemedyToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract DecisionCorrectionIntegrationTest is DecisionSetFixture {
    address private constant BENEFICIARY = address(0xB1);

    struct Positive {
        uint256 requestId;
        uint256 executionId;
        uint256 decisionId;
    }

    function setUp() public override {
        super.setUp();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVARequestCorrectionActions.FILE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
    }

    function testGenericWithdrawalRequiresFreshExecutionAndChoiceAndRetainsBothHistories() public {
        IAVADecisionPolicy.Request memory input = _input("generic withdrawal");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 oldExecution = _execution(input, pool, PARAMETERS);
        uint256 oldDecision = _choose(id, POSITIVE, oldExecution, 0);
        bytes32 decisionHash = keccak256(abi.encode(registry.getDecision(oldDecision)));
        bytes32 requestHash = keccak256(abi.encode(requestAllocation.getRequest(oldExecution)));
        uint256 challenge = _file(oldExecution, AVARequestAllocation.ChallengeTarget.Allocation);
        require(
            requestAllocation.validateExecution(oldExecution, RESPONSE, PARAMETERS, address(executor)),
            "filing alone changed execution"
        );
        _resolve(_resolution(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, _authority(ROLE_VERIFIER)));
        _assertChallenge(challenge, oldExecution, AVARequestAllocation.ResolutionOutcome.Withdrawn);
        require(requestAllocation.withdrawalResolutionIdByRequest(oldExecution) == challenge, "withdrawal link");
        require(keccak256(abi.encode(requestAllocation.getRequest(oldExecution))) == requestHash, "allocation erased");
        require(keccak256(abi.encode(registry.getDecision(oldDecision))) == decisionHash, "decision erased");
        requestVm.expectRevert();
        executor.execute(requestAllocation, oldExecution, RESPONSE, PARAMETERS);

        uint256 successor = _execution(input, pool, PARAMETERS);
        AVARequestAllocation.RequestRecord memory fresh = requestAllocation.getRequest(successor);
        require(
            fresh.supersedesRequestId == oldExecution
                && requestAllocation.supersededByRequest(oldExecution) == successor,
            "execution history link"
        );
        require(fresh.allocator == address(0) && fresh.approvedAt == 0, "successor inherited approval");
        require(
            requestAllocation.decisionRequestIdByExecution(successor) == id
                && requestAllocation.supportWitnessHash(successor) != requestAllocation.supportWitnessHash(oldExecution)
                && keccak256(abi.encode(requestAllocation.getSupportWitness(successor)))
                    == keccak256(abi.encode(requestAllocation.getSupportWitness(oldExecution))),
            "generic support link"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, successor, RESPONSE, PARAMETERS);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, POSITIVE, successor, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        uint256 nextDecision = _choose(id, POSITIVE, successor, oldDecision);
        AVADecisionRegistry.DecisionRecord memory selected = registry.getDecision(nextDecision);
        require(
            selected.requestId == id && selected.previousDecisionId == oldDecision
                && selected.executionRequestId == successor && selected.actor == ALLOCATOR_ACTOR
                && selected.authorityId == _authority(ROLE_ALLOCATOR),
            "fresh choice binding"
        );
        require(
            selected.witnessHash == registry.getDecision(oldDecision).witnessHash && selected.witness.length == 1
                && selected.witness[0].recognisedStateId == pool[0].recognisedStateId
                && selected.witness[0].transitionId == pool[0].transitionId,
            "selected witness changed"
        );
        executor.execute(requestAllocation, successor, RESPONSE, PARAMETERS);
        _assertCompleted(successor);
        require(!requestAllocation.getRequest(oldExecution).consumed, "withdrawn predecessor executed");
        require(keccak256(abi.encode(registry.getDecision(oldDecision))) == decisionHash, "old choice overwritten");
        require(
            kernel.getRecognisedStateReference(pool[0].recognisedStateId).lastTransitionId == pool[0].transitionId,
            "allocation correction changed recognition"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, oldExecution, RESPONSE, PARAMETERS);
    }

    function testGenericCompletedEffectRetainsHistoryThroughSourceLossUpgradeAndCurrentResolverReview() public {
        Positive memory chosen = _positive("historical generic effect");
        executor.execute(requestAllocation, chosen.executionId, RESPONSE, PARAMETERS);
        bytes32 executionHash = keccak256(abi.encode(requestAllocation.getRequest(chosen.executionId)));
        bytes32 decisionHash = keccak256(abi.encode(registry.getDecision(chosen.decisionId)));
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(chosen.executionId);
        _change(
            original.input.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Voided,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.warp(uint256(original.input.validUntil) + 1);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        require(requestPackageId != original.packageId, "package not superseded");
        require(registry.getEligibleWitnesses(chosen.requestId).length == 0, "voided source eligible");

        uint256 challenge = _file(chosen.executionId, AVARequestAllocation.ChallengeTarget.Effect);
        AVARequestAllocation.ResolutionInput memory resolution =
            _resolution(challenge, AVARequestAllocation.ResolutionOutcome.Residual, _authority(ROLE_VERIFIER));
        identityRegistry.deactivateSubject(_authority(ROLE_VERIFIER));
        bytes32 currentResolver = keccak256("generic correction current resolver");
        identityRegistry.assignSubject(VERIFIER_ACTOR, APP, ROLE_VERIFIER, currentResolver, "test:current-resolver");
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(resolution);
        require(requestAllocation.lastResolutionIdByRequest(chosen.executionId) == 0, "stale resolver wrote decision");
        resolution = _resolution(challenge, AVARequestAllocation.ResolutionOutcome.Residual, currentResolver);
        _resolve(resolution);
        _assertChallenge(challenge, chosen.executionId, AVARequestAllocation.ResolutionOutcome.Residual);
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            receipt.resolverAuthorityId == currentResolver
                && identityRegistry.subjectOf(VERIFIER_ACTOR, APP, ROLE_VERIFIER) == currentResolver,
            "resolver is not current canonical subject"
        );
        require(
            receipt.completedAtFiling && receipt.consumedAtResolution && receipt.completedAtResolution
                && receipt.effectHashAtResolution == original.effectHash
                && receipt.sourceStatusAtResolution == AVACoreTypes.RecognisedStateStatus.Voided
                && receipt.sourceTransitionIdAtResolution != original.recognisedStateTransitionId,
            "historical correction context"
        );
        require(requestAllocation.withdrawalResolutionIdByRequest(chosen.executionId) == 0, "effect withdrawn");
        require(
            keccak256(abi.encode(requestAllocation.getRequest(chosen.executionId))) == executionHash, "effect erased"
        );
        require(keccak256(abi.encode(registry.getDecision(chosen.decisionId))) == decisionHash, "choice erased");
        requestVm.expectRevert();
        executor.execute(requestAllocation, chosen.executionId, RESPONSE, PARAMETERS);
    }

    function testGenericCompletedEffectCompensationTransfersFreshFundsToFixedRecipientOnce() public {
        Positive memory chosen = _positive("generic compensated effect");
        executor.execute(requestAllocation, chosen.executionId, RESPONSE, PARAMETERS);
        bytes32 executionHash = keccak256(abi.encode(requestAllocation.getRequest(chosen.executionId)));
        bytes32 decisionHash = keccak256(abi.encode(registry.getDecision(chosen.decisionId)));
        uint256 challenge = _file(chosen.executionId, AVARequestAllocation.ChallengeTarget.Effect);
        DecisionRemedyToken asset = new DecisionRemedyToken();
        AVARequestAllocation.ResolutionInput memory resolution =
            _resolution(challenge, AVARequestAllocation.ResolutionOutcome.Compensate, _authority(ROLE_VERIFIER));
        resolution.remedy = AVARequestAllocation.RemedyTerms(address(asset), BENEFICIARY, 100);
        _resolve(resolution);
        _assertChallenge(challenge, chosen.executionId, AVARequestAllocation.ResolutionOutcome.Compensate);
        AVARequestAllocation.CompensationRecord memory remedy = requestAllocation.getCompensation(challenge);
        require(
            remedy.terms.asset == address(asset) && remedy.terms.recipient == BENEFICIARY && remedy.terms.amount == 100
                && !remedy.funded && !remedy.paid,
            "authorization confused with payment"
        );
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        requestAllocation.fundCompensation(challenge);
        require(
            asset.balanceOf(address(this)) == 0 && asset.balanceOf(address(requestAllocation)) == 100
                && asset.balanceOf(BENEFICIARY) == 0,
            "funding did not escrow exact assets"
        );
        remedy = requestAllocation.getCompensation(challenge);
        require(remedy.funded && !remedy.paid && remedy.funder == address(this), "funding receipt");
        requestVm.expectRevert();
        requestAllocation.fundCompensation(challenge);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        requestVm.warp(uint256(requestAllocation.getRequest(chosen.executionId).input.validUntil) + 1);
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(challenge);
        remedy = requestAllocation.getCompensation(challenge);
        require(remedy.paid && remedy.paymentHash != bytes32(0) && remedy.paidAt > remedy.fundedAt, "payment receipt");
        require(
            asset.balanceOf(BENEFICIARY) == 100 && asset.balanceOf(address(requestAllocation)) == 0,
            "fixed recipient payment"
        );
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(chosen.executionId))) == executionHash, "effect replaced"
        );
        require(keccak256(abi.encode(registry.getDecision(chosen.decisionId))) == decisionHash, "decision replaced");
    }

    function testCompletedGenericMeaningCannotBeRechosenOrReplayedUnderFreshRequestHash() public {
        Positive memory chosen = _positive("completed original meaning");
        executor.execute(requestAllocation, chosen.executionId, RESPONSE, PARAMETERS);
        _assertCompleted(chosen.executionId);
        uint256 nextDecision = registry.nextDecisionId();
        require(_d(chosen.requestId).length == 0, "completed positive re-admitted");
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(
            chosen.requestId,
            POSITIVE,
            chosen.executionId,
            chosen.decisionId,
            ROLE_ALLOCATOR,
            _authority(ROLE_ALLOCATOR),
            REASON
        );
        IAVADecisionPolicy.Request memory input = _input("fresh hash completed meaning");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 fresh = _open(input, pool);
        require(registry.getEligibleWitnesses(fresh).length == 1, "fresh request lacks live evidence");
        require(_d(fresh).length == 0, "fresh hash replayed completed meaning");
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createDecisionRequest(
            fresh, _executionInput(input, pool, PARAMETERS), pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, chosen.executionId, RESPONSE, PARAMETERS);
        require(registry.nextDecisionId() == nextDecision, "failed replay appended decision");
        require(
            registry.getRequest(chosen.requestId).allocationDecisionId == chosen.decisionId, "choice pointer changed"
        );
    }

    function _positive(bytes32 requestHash) private returns (Positive memory chosen) {
        IAVADecisionPolicy.Request memory input = _input(requestHash);
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        chosen.requestId = _open(input, pool);
        chosen.executionId = _execution(input, pool, PARAMETERS);
        chosen.decisionId = _choose(chosen.requestId, POSITIVE, chosen.executionId, 0);
    }

    function _file(uint256 executionId, AVARequestAllocation.ChallengeTarget target) private returns (uint256) {
        uint256 evidence = _correctionEvidence(SOURCE_ACTOR, ROLE_SOURCE, _authority(ROLE_SOURCE), executionId);
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.fileRequestChallenge(
            executionId, target, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
    }

    function _resolution(uint256 challenge, AVARequestAllocation.ResolutionOutcome outcome, bytes32 resolver)
        private
        returns (AVARequestAllocation.ResolutionInput memory)
    {
        uint256 executionId = requestAllocation.getRequestChallenge(challenge).requestId;
        return AVARequestAllocation.ResolutionInput({
            challengeId: challenge,
            expectedPreviousResolutionId: requestAllocation.lastResolutionIdByRequest(executionId),
            roleKey: ROLE_VERIFIER,
            authorityId: resolver,
            decisionEvidenceId: _correctionEvidence(VERIFIER_ACTOR, ROLE_VERIFIER, resolver, executionId),
            outcome: outcome,
            reasonHash: keccak256("independent generic correction"),
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(
                outcome == AVARequestAllocation.ResolutionOutcome.Rejected
                    || outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn
                    || outcome == AVARequestAllocation.ResolutionOutcome.Residual
                    || outcome == AVARequestAllocation.ResolutionOutcome.Compensate
            )
        });
    }

    function _resolve(AVARequestAllocation.ResolutionInput memory input) private {
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
    }

    function _correctionEvidence(address actor, bytes32 role, bytes32 authority, uint256 executionId)
        private
        returns (uint256)
    {
        uint256 historicalPackage = requestAllocation.getRequest(executionId).packageId;
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: historicalPackage,
            roleKey: role,
            subjectId: authority,
            commitment: keccak256(abi.encode("generic correction evidence", evidenceRegistry.nextEvidenceId())),
            evidenceTypeHash: keccak256("generic correction"),
            disclosurePolicyId: requestPolicyId,
            authorityId: authority,
            uri: "test:generic-correction"
        });
        if (historicalPackage == requestPackageId) {
            requestVm.prank(actor);
            return evidenceRegistry.registerEvidence(input);
        }
        authorityMatrix.setPermission(APP, role, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        requestVm.prank(actor);
        return evidenceRegistry.registerCorrectionEvidence(input, requestPackageId, REASON);
    }

    function _assertChallenge(uint256 challenge, uint256 executionId, AVARequestAllocation.ResolutionOutcome outcome)
        private
        view
    {
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            receipt.requestId == executionId && receipt.outcome == outcome && receipt.filedBy == SOURCE_ACTOR
                && receipt.resolvedBy == VERIFIER_ACTOR && receipt.resolvedBy != receipt.filedBy
                && receipt.resolvedBy != requestAllocation.getRequest(executionId).allocator && receipt.evidenceId != 0
                && receipt.decisionEvidenceId != 0 && receipt.resolutionHash != bytes32(0)
                && requestAllocation.lastResolutionIdByRequest(executionId) == challenge,
            "independent challenge linkage"
        );
        uint256 genericId = requestAllocation.decisionRequestIdByExecution(executionId);
        uint256 decisionId = registry.getRequest(genericId).allocationDecisionId;
        require(registry.getDecision(decisionId).executionRequestId == executionId, "challenge lost generic choice");
    }

    function _assertCompleted(uint256 executionId) private view {
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(executionId);
        require(
            record.consumed && record.completed
                && record.effectHash == keccak256(abi.encode("decision effect", executionId))
                && record.allocator == ALLOCATOR_ACTOR && record.triggeredBy == address(this),
            "atomic generic effect missing"
        );
    }
}
