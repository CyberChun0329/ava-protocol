// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVAExecutionLifecycle} from "../src/extensions/requests/AVAExecutionLifecycle.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";
import {FencedLocalEffect} from "./ExecutionRecovery.t.sol";

/// @notice One real-Core composition witness; existing suites cover each individual mechanism.
contract LifecycleCombinationTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("lifecycle.combination.app");
    bytes32 private constant RESPONSE = keccak256("lifecycle.combination.response");
    bytes32 private constant REVIEW_ROLE = keccak256("lifecycle.combination.review.role");
    bytes32 private constant REPLACEMENT_REVIEWER = keccak256("lifecycle.combination.review.replacement");
    bytes32 private constant REASON = keccak256("lifecycle.combination.reason");
    address private constant REVIEWER = address(0xD1);

    FencedLocalEffect private executor;
    M14PermissiveApplicationModule private application;

    function setUp() public {
        application = new M14PermissiveApplicationModule(APP);
        _setUpRequestAllocation(APP, application, keccak256("lifecycle.combination.object"));
        executor = new FencedLocalEffect(requestAllocation);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_AUTHORISE_RECOVERY(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        identityRegistry.assignSubject(REVIEWER, APP, REVIEW_ROLE, _authority(REVIEW_ROLE), "test:reviewer");
        authorityMatrix.setPermission(APP, REVIEW_ROLE, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
    }

    function testVersionChangeEvidenceLossAndIndependentReviewRetainOnlyLawfulRecovery() public {
        bytes memory data = abi.encode(uint256(1));
        uint256 id = _split(data);
        uint256 other = _split(abi.encode(uint256(2)));
        uint256 attempt = executor.start(id, RESPONSE, keccak256(data));
        uint256 otherAttempt = executor.start(other, RESPONSE, keccak256(abi.encode(uint256(2))));
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        bytes32 requestHistory = keccak256(abi.encode(original));
        bytes32 sourceHistory =
            keccak256(abi.encode(kernel.getRecognisedStateReference(original.input.recognisedStateId)));
        bytes32 sourceTransition =
            keccak256(abi.encode(kernel.getRecognisedStateTransition(original.recognisedStateTransitionId)));

        // The local effect really fails and rolls back; a report alone is not effect evidence.
        executor.configure(executor.configuration(), true);
        requestVm.expectRevert();
        executor.finish(id, attempt, data);
        require(executor.effects() == 0, "failed effect escaped rollback");
        executor.configure(executor.configuration(), false);
        uint256 first = _noEffect(id, attempt, "first observation");
        uint256 oldEvidence = _evidence(VERIFIER_ACTOR, ROLE_VERIFIER, original.packageId);
        uint256 staleRecovery = _authorise(id, first, oldEvidence);
        uint256 latest = _noEffect(id, attempt, "new observation");
        bytes32 firstReport = keccak256(abi.encode(requestAllocation.EXECUTION().getReport(first)));
        bytes32 retiredAttempt = keccak256(abi.encode(requestAllocation.EXECUTION().getAttempt(attempt)));
        bytes32 staleDecision = keccak256(abi.encode(requestAllocation.EXECUTION().getRecovery(staleRecovery)));

        uint256 filingEvidence = _evidence(SOURCE_ACTOR, ROLE_SOURCE, original.packageId);
        requestVm.prank(SOURCE_ACTOR);
        uint256 challenge = requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            filingEvidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        uint256 caseId = requestAllocation.correctionReviewCaseIdByChallenge(challenge);
        IAVACorrectionReview.CaseRecord memory accepted = kernel.CORRECTIONS().getCase(caseId);

        requestPackageId = _registerRequestPackage(application, 2);
        require(requestPackageId != original.packageId, "rule version did not change");
        _revoke(filingEvidence, SOURCE_ACTOR, ROLE_SOURCE);
        _revoke(oldEvidence, VERIFIER_ACTOR, ROLE_VERIFIER);
        _independentAffirmation(caseId, original.packageId);
        require(
            requestAllocation.getRequestChallenge(challenge).outcome == AVARequestAllocation.ResolutionOutcome.Rejected,
            "independent affirmation did not dispose the concern"
        );
        require(
            keccak256(abi.encode(kernel.CORRECTIONS().getCase(caseId).input)) == keccak256(abi.encode(accepted.input)),
            "accepted historical case rewritten"
        );
        require(
            !requestAllocation.getRequest(id).completed
                && requestAllocation.EXECUTION().getDeclaration(id).latestAttemptId == attempt,
            "review fabricated completion or retry"
        );

        requestVm.expectRevert();
        executor.recover(id, staleRecovery);
        uint256 freshEvidence = _evidence(VERIFIER_ACTOR, ROLE_VERIFIER, original.packageId);
        requestVm.expectRevert();
        _authorise(id, first, freshEvidence);
        requestVm.expectRevert();
        _authorise(id, latest, oldEvidence);

        // A separate contradictory occurrence stays frozen under the same current rules and authority.
        uint256 contradiction = executor.report(
            other, otherAttempt, AVAExecutionLifecycle.ReportKind.ContradictoryEffect, keccak256("observed effect")
        );
        uint256 laterAssertion = _noEffect(other, otherAttempt, "later no-effect assertion");
        requestVm.expectRevert();
        _authorise(other, laterAssertion, freshEvidence);
        requestVm.expectRevert();
        executor.finish(other, otherAttempt, abi.encode(uint256(2)));
        require(requestAllocation.EXECUTION().getDeclaration(other).frozen, "contradiction erased");
        require(
            requestAllocation.EXECUTION().getReport(contradiction).kind
                == AVAExecutionLifecycle.ReportKind.ContradictoryEffect,
            "contradictory report lost"
        );
        require(executor.effects() == 0, "denied path applied an effect");

        uint256 recovery = _authorise(id, latest, freshEvidence);
        uint256 replacement = executor.recover(id, recovery);
        require(
            requestAllocation.EXECUTION().getAttempt(replacement).previousAttemptId == attempt
                && requestAllocation.EXECUTION().getAttempt(replacement).recoveryId == recovery,
            "recovery lineage missing"
        );
        executor.finish(id, replacement, data);
        require(executor.effects() == 1 && requestAllocation.getRequest(id).completed, "lawful recovery effect absent");
        require(requestAllocation.EXECUTION().getRecovery(recovery).used, "recovery use absent");
        require(requestAllocation.EXECUTION().getAttempt(replacement).completed, "replacement completion absent");

        // Only the completion fields may change; source, allocation and first consumption stay exact.
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(id);
        completed.completed = false;
        completed.completedAt = 0;
        completed.effectHash = bytes32(0);
        require(keccak256(abi.encode(completed)) == requestHistory, "original request/approval/consumption rewritten");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateReference(original.input.recognisedStateId))) == sourceHistory
                && keccak256(abi.encode(kernel.getRecognisedStateTransition(original.recognisedStateTransitionId)))
                    == sourceTransition,
            "original Core source history rewritten"
        );
        require(
            keccak256(abi.encode(requestAllocation.EXECUTION().getReport(first))) == firstReport
                && keccak256(abi.encode(requestAllocation.EXECUTION().getAttempt(attempt))) == retiredAttempt
                && keccak256(abi.encode(requestAllocation.EXECUTION().getRecovery(staleRecovery))) == staleDecision,
            "execution history rewritten"
        );
        bytes32 effectHistory = keccak256(abi.encode(requestAllocation.EXECUTION().getAttempt(replacement)));
        requestVm.expectRevert();
        executor.finish(id, attempt, data);
        requestVm.expectRevert();
        executor.recover(id, recovery);
        requestVm.expectRevert();
        executor.finish(id, replacement, data);
        require(executor.effects() == 1, "duplicate local effect");
        require(
            keccak256(abi.encode(requestAllocation.EXECUTION().getAttempt(replacement))) == effectHistory,
            "completed effect history rewritten"
        );
    }

    function _independentAffirmation(uint256 caseId, uint256 historicalPackage) private {
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        identityRegistry.deactivateSubject(_authority(REVIEW_ROLE));
        identityRegistry.assignSubject(REVIEWER, APP, REVIEW_ROLE, REPLACEMENT_REVIEWER, "test:current-reviewer");
        AVAEvidenceRegistry.EvidenceRegistrationInput memory retiredInput =
            _evidenceInput(REVIEW_ROLE, _authority(REVIEW_ROLE), historicalPackage);
        requestVm.expectRevert();
        requestVm.prank(REVIEWER);
        evidenceRegistry.registerReviewEvidence(retiredInput, corrections, caseId);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory currentInput =
            _evidenceInput(REVIEW_ROLE, REPLACEMENT_REVIEWER, historicalPackage);
        requestVm.prank(REVIEWER);
        uint256 support = evidenceRegistry.registerReviewEvidence(currentInput, corrections, caseId);
        requestVm.prank(REVIEWER);
        uint256 review = corrections.review(
            IAVACorrectionReview.ReviewInput({
                caseId: caseId,
                expectedTargetVersion: 0,
                outcome: IAVACorrectionReview.Outcome.Affirmed,
                evidenceId: support,
                roleKey: REVIEW_ROLE,
                authorityId: REPLACEMENT_REVIEWER,
                reasonHash: REASON,
                asset: address(0),
                recipient: address(0),
                amount: 0,
                finding: _findingInput(true)
            })
        );
        IAVACorrectionReview.RecognisedFinding memory finding =
            corrections.getFinding(corrections.findingIdByCase(caseId));
        require(finding.independentReview && finding.verifier == REVIEWER, "independent finding absent");
        require(finding.verifierAuthorityId == REPLACEMENT_REVIEWER, "retired reviewer authority reused");
        require(corrections.getCase(caseId).reviewId == review && corrections.activeReviewId() == 0, "review not final");
    }

    function _split(bytes memory data) private returns (uint256 id) {
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 state = _createRequestState(address(executor), RESPONSE, keccak256(data), REASON, expiry);
        id = _createRequest(
            AVARequestAllocation.RequestInput(state, address(executor), RESPONSE, keccak256(data), REASON, expiry)
        );
        bytes32 configuration = executor.configuration();
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.declareSplitMode(id, configuration);
        _approveRequest(id);
    }

    function _noEffect(uint256 id, uint256 attempt, string memory observation) private returns (uint256) {
        return
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256(bytes(observation)));
    }

    function _authorise(uint256 id, uint256 report, uint256 evidence) private returns (uint256) {
        requestVm.prank(VERIFIER_ACTOR);
        return requestAllocation.authoriseRecovery(
            AVAExecutionLifecycle.RecoveryInput(id, report, evidence, ROLE_VERIFIER, _authority(ROLE_VERIFIER), REASON)
        );
    }

    function _revoke(uint256 evidence, address actor, bytes32 role) private {
        requestVm.prank(actor);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence, role, _authority(role), AVACoreTypes.EvidenceLifecycleKind.Revoke, 0, REASON, "test:lost-evidence"
        );
        require(
            evidenceRegistry.getEvidenceReference(evidence).status == AVACoreTypes.EvidenceStatus.Revoked,
            "evidence not revoked"
        );
    }

    function _evidence(address actor, bytes32 role, uint256 historicalPackage) private returns (uint256) {
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input =
            _evidenceInput(role, _authority(role), historicalPackage);
        requestVm.prank(actor);
        if (historicalPackage == requestPackageId) return evidenceRegistry.registerEvidence(input);
        return evidenceRegistry.registerCorrectionEvidence(input, requestPackageId, REASON);
    }

    function _evidenceInput(bytes32 role, bytes32 authority, uint256 packageId)
        private
        view
        returns (AVAEvidenceRegistry.EvidenceRegistrationInput memory)
    {
        return AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: packageId,
            roleKey: role,
            subjectId: authority,
            commitment: keccak256(abi.encode(REASON, evidenceRegistry.nextEvidenceId())),
            evidenceTypeHash: REASON,
            disclosurePolicyId: requestPolicyId,
            authorityId: authority,
            uri: "test:combination-support"
        });
    }
}
