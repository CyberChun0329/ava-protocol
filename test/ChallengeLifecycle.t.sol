// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {AVAChallengeExtension} from "../src/extensions/challenge/AVAChallengeExtension.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAAntiAbusePolicyModule
} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @notice Historical package policies may reject even a neutral resolution.
contract ChallengeResolutionRejectPolicy is
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAAntiAbusePolicyModule,
    RuleModuleIdentity
{
    function validateChallenge(ChallengeContext calldata context) external pure {
        require(context.actionKey != AVACoreTypes.ACTION_RESOLVE_CHALLENGE, "challenge policy rejected");
    }

    function validateAuthority(AuthorityContext calldata context) external pure {
        require(context.actionKey != AVACoreTypes.ACTION_RESOLVE_CHALLENGE, "authority policy rejected");
    }

    function validateAntiAbuse(AntiAbuseContext calldata context) external pure {
        require(context.actionKey != AVACoreTypes.ACTION_RESOLVE_CHALLENGE, "anti-abuse policy rejected");
    }
}

/// @notice Asserts the exact selected-evidence commitment at the historical authority-policy boundary.
contract ExactChallengeDecisionHashPolicy is IAVAAuthorityPolicyModule, RuleModuleIdentity {
    AVAChallengeExtension private immutable challenges;

    constructor(AVAChallengeExtension challenges_) {
        challenges = challenges_;
    }

    function validateAuthority(AuthorityContext calldata context) external view {
        if (context.actionKey != AVACoreTypes.ACTION_RESOLVE_CHALLENGE) return;
        AVAChallengeExtension.ChallengeRecord memory challenge = challenges.getChallenge(context.targetId);
        require(challenge.decisionEvidenceReceiptId != challenge.evidenceReceiptId, "fresh support not selected");
        bytes32 expectedHash = keccak256(
            abi.encode(
                challenge.id,
                AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                challenge.targetTransitionIdAtFiling,
                AVAChallengeExtension.ChallengeOutcome.Upheld,
                keccak256(abi.encode("resolution", challenge.id, AVAChallengeExtension.ChallengeOutcome.Upheld)),
                challenge.packageId,
                challenge.targetPackageId,
                challenge.evidenceReceiptId,
                challenge.decisionEvidenceReceiptId
            )
        );
        require(context.decisionHash == expectedHash, "selected evidence decision hash mismatch");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(address(challenges)));
    }
}

/// @notice All lifecycle changes use the deployed Core and extension public APIs.
contract ChallengeLifecycleTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("challenge.lifecycle.test.app");
    bytes32 private constant CHALLENGER_SUBJECT = keccak256("challenge.lifecycle.challenger");
    bytes32 private constant DECISION_SUBJECT = keccak256("challenge.lifecycle.decision-author");
    address private constant CHALLENGER = address(0xC3);
    address private constant DECISION_AUTHOR = address(0xC4);
    AVAChallengeExtension private challenges;
    uint256 private targetId;
    uint256 private challengeId;
    uint256 private filingEvidenceId;
    uint256 private challengeStateId;
    uint256 private filingHistoryId;

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("challenge.test.target"));
        identityRegistry.assignSubject(CHALLENGER, APP, ROLE_SOURCE, CHALLENGER_SUBJECT, "test:challenger");
        identityRegistry.assignSubject(DECISION_AUTHOR, APP, ROLE_SOURCE, DECISION_SUBJECT, "test:decision-author");
        challenges =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FILE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_SCREEN_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_CLOSE_CHALLENGE, true);
        targetId = _createStateForCommitment(keccak256("challenge.lifecycle.target"));
        (challengeId, filingEvidenceId, challengeStateId) = _file(targetId, keccak256("first"));
        filingHistoryId = challenges.getChallenge(challengeId).lastTransitionId;
    }

    function testAcceptedChallengeCannotCloseWithoutExplicitResolution() public {
        _screen(challengeId);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.closeChallenge(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("close"), "test:close"
        );
    }

    function testRevokedFilingEvidenceCanResolveUnavailableAfterScreening() public {
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        uint256 targetTransition = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 challengeTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        uint256 resolution = _resolve(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(challengeId);
        require(record.outcome == AVAChallengeExtension.ChallengeOutcome.Unavailable, "not explicitly unavailable");
        require(record.status == AVAChallengeExtension.ChallengeStatus.Resolved, "not resolved");
        require(
            record.evidenceReceiptId == filingEvidenceId && record.decisionEvidenceReceiptId == 0, "filing rewritten"
        );
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == targetTransition, "target changed");
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == challengeTransition,
            "challenge vested"
        );
        require(
            challenges.getChallengeTransition(resolution).kind
                == AVAChallengeExtension.ChallengeTransitionKind.Resolution,
            "not Resolution"
        );
    }

    function testUnavailableBeforeScreeningAfterRevoke() public {
        _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind.Revoke, false);
    }

    function testUnavailableBeforeScreeningAfterExpire() public {
        _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind.Expire, false);
    }

    function testUnavailableAfterScreeningAfterExpire() public {
        _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind.Expire, true);
    }

    function testUnavailableBeforeScreeningAfterSupersede() public {
        _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind.Supersede, false);
    }

    function testUnavailableAfterScreeningAfterSupersede() public {
        _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind.Supersede, true);
    }

    function testInactiveChallengerCanGetNeutralResolutionBeforeScreening() public {
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        _resolveUnavailableAndAssert();
    }

    function testInactiveChallengerCanGetNeutralResolutionAfterScreening() public {
        _screen(challengeId);
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        _resolveUnavailableAndAssert();
    }

    function testActiveFilingCannotBeDismissedAsUnavailable() public {
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
        _screen(challengeId);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
        uint256 fresh = _freshEvidence();
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, fresh);
        require(
            challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.None,
            "mislabelled merits"
        );
    }

    function testUnavailableCannotCorrectTargetOrUseFabricatedDecisionEvidence() public {
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        uint256 fresh = _freshEvidence();
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, fresh);
        AVAChallengeExtension.ChallengeResolutionInput memory input =
            _resolution(AVAChallengeExtension.ChallengeOutcome.Unavailable);
        input.correctionStatus = AVACoreTypes.RecognisedStateStatus.Voided;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(input, 0);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.MaliciousOrFabricated, 0);
    }

    function testUnavailableRequiresCurrentResolverPermission() public {
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, false);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
    }

    function testUnavailableRequiresActiveResolverSubject() public {
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        identityRegistry.deactivateSubject(_authority(ROLE_VERIFIER));
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
    }

    function testUnauthorizedAndConflictedAccountsCannotResolveUnavailable() public {
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        AVAChallengeExtension.ChallengeResolutionInput memory input =
            _resolution(AVAChallengeExtension.ChallengeOutcome.Unavailable);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(input, 0);
        bytes32 targetResolver = keccak256("target.resolver");
        identityRegistry.assignSubject(SOURCE_ACTOR, APP, ROLE_VERIFIER, targetResolver, "test:target-resolver");
        input.authorityId = targetResolver;
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(input, 0);
        bytes32 challengerResolver = keccak256("challenger.resolver");
        identityRegistry.assignSubject(CHALLENGER, APP, ROLE_VERIFIER, challengerResolver, "test:challenger-resolver");
        input.authorityId = challengerResolver;
        requestVm.prank(CHALLENGER);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(input, 0);
    }

    function testHistoricalChallengePolicyCanRejectNeutralResolution() public {
        _policyRejection(0);
    }

    function testHistoricalAuthorityPolicyCanRejectNeutralResolution() public {
        _policyRejection(1);
    }

    function testHistoricalAntiAbusePolicyCanRejectNeutralResolution() public {
        _policyRejection(2);
    }

    function testDistinctHistoricalPackagesBindExactSelectedEvidenceDecisionHash() public {
        uint256 originalPackage = requestPackageId;
        targetId = _createStateForCommitment(keccak256("distinct-package.target"));
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _coreBindings(new M14PermissiveApplicationModule(APP));
        bindings[7] =
            _coreBinding(AVACapabilityKeys.AUTHORITY_POLICY, address(new ExactChallengeDecisionHashPolicy(challenges)));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:exact-decision-hash"
            ),
            originalPackage,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        (challengeId, filingEvidenceId, challengeStateId) = _file(targetId, keccak256("distinct-package.challenge"));
        _screen(challengeId);
        uint256 fresh = _freshEvidence();
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
        AVAChallengeExtension.ChallengeRecord memory challenge = challenges.getChallenge(challengeId);
        require(
            challenge.packageId == requestPackageId && challenge.targetPackageId == originalPackage,
            "historical packages collapsed"
        );
        require(challenge.decisionEvidenceReceiptId == fresh, "selected evidence lost");
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "distinct-package correction missing"
        );
    }

    function testDistinctTargetHistoricalChallengePolicyCannotBeBypassed() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _coreBindings(new M14PermissiveApplicationModule(APP));
        bindings[6] = _coreBinding(AVACapabilityKeys.CHALLENGE_POLICY, address(new ChallengeResolutionRejectPolicy()));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:target-reject-policy"
            ),
            requestPackageId,
            bindings
        );
        uint256 targetPackage = requestPackageId;
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        targetId = _createStateForCommitment(keccak256("distinct-package.reject-target"));
        requestPackageId = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 3);
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        (challengeId, filingEvidenceId, challengeStateId) =
            _file(targetId, keccak256("distinct-package.allowed-challenge"));
        _screen(challengeId);
        uint256 fresh = _freshEvidence();
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
        AVAChallengeExtension.ChallengeRecord memory challenge = challenges.getChallenge(challengeId);
        require(
            challenge.packageId != targetPackage && challenge.targetPackageId == targetPackage, "not distinct packages"
        );
        require(
            challenge.status == AVAChallengeExtension.ChallengeStatus.AdmissibilityScreening,
            "historical rejection bypassed"
        );
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "rejected correction leaked"
        );
    }

    function testRevokedTargetEvidenceCannotAdvertiseRestorationAndResolvedChallengeCanClose() public {
        _lostTargetEvidenceBeforeRestoration(AVACoreTypes.EvidenceLifecycleKind.Revoke);
    }

    function testExpiredTargetEvidenceCannotAdvertiseRestorationAndResolvedChallengeCanClose() public {
        _lostTargetEvidenceBeforeRestoration(AVACoreTypes.EvidenceLifecycleKind.Expire);
    }

    function testSupersededTargetEvidenceCannotAdvertiseRestorationAndResolvedChallengeCanClose() public {
        _lostTargetEvidenceBeforeRestoration(AVACoreTypes.EvidenceLifecycleKind.Supersede);
    }

    function testInactiveTargetSubjectCannotAdvertiseRestorationAndResolvedChallengeCanClose() public {
        _screen(challengeId);
        identityRegistry.deactivateSubject(kernel.getRecognisedStateReference(targetId).subjectId);
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, _freshEvidence());
        _expectAvailabilityRevertAndClose();
    }

    function testTargetEvidenceLossAfterAvailabilityBlocksRestorationWithoutErasingResolution() public {
        _makeRestorationAvailable();
        _invalidateTargetEvidence(AVACoreTypes.EvidenceLifecycleKind.Revoke);
        _expectRestorationRevertAndClose();
    }

    function testTargetSubjectLossAfterAvailabilityBlocksRestorationWithoutErasingResolution() public {
        _makeRestorationAvailable();
        identityRegistry.deactivateSubject(kernel.getRecognisedStateReference(targetId).subjectId);
        _expectRestorationRevertAndClose();
    }

    function testFreshEvidenceCorrectsTargetWithRevokedFilingAndInactiveChallenger() public {
        _screen(challengeId);
        uint256 fresh = _freshEvidence();
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        uint256 oldChallengeTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        uint256 resolution = _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(challengeId);
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "target not corrected"
        );
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == oldChallengeTransition,
            "old challenge changed"
        );
        require(
            record.evidenceReceiptId == filingEvidenceId && record.decisionEvidenceReceiptId == fresh,
            "evidence identity lost"
        );
        require(
            challenges.getChallengeTransition(resolution).decisionEvidenceReceiptId == fresh, "resolution support lost"
        );
        require(
            challenges.getChallengeTransition(filingHistoryId).evidenceReceiptId == filingEvidenceId,
            "filing history lost"
        );
        require(
            challenges.getChallengeTransition(filingHistoryId).decisionEvidenceReceiptId == 0,
            "filing history rewritten"
        );
        require(
            kernel.getRecognisedStateTransitionReference(record.targetTransitionIdAfterResolution)
            .decisionEvidenceReceiptId == fresh,
            "kernel used original evidence"
        );
        requestVm.prank(VERIFIER_ACTOR);
        challenges.recordRestorationAvailability(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore.available"), "test:restore"
        );
        requestVm.prank(VERIFIER_ACTOR);
        challenges.applyRestoration(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore"), "test:restore"
        );
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Restored,
            "not restored"
        );
        require(
            challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.Closed, "not closed"
        );
        uint256 restoredTransition = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        require(
            kernel.getRecognisedStateTransitionReference(restoredTransition).decisionEvidenceReceiptId == fresh,
            "restoration used old receipt"
        );
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "open count retained");
    }

    function testSupersedingReceiptCanSupportCorrectionWithoutVestingOldChallenge() public {
        _screen(challengeId);
        uint256 replacement =
            _evidence(CHALLENGER, CHALLENGER_SUBJECT, keccak256("replacement"), requestPackageId, REQUEST_WORKFLOW);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Supersede, replacement);
        uint256 beforeTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, replacement);
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == beforeTransition,
            "old superseded state vested"
        );
        require(challenges.getChallenge(challengeId).evidenceReceiptId == filingEvidenceId, "replaced filing history");
    }

    function testMeritsResolutionFormsLimitedFindingAndPreservesFiledAllegation() public {
        _screen(challengeId);
        AVAChallengeExtension.ChallengeResolutionInput memory input =
            _resolution(AVAChallengeExtension.ChallengeOutcome.Upheld);
        bytes32 originalHistory = keccak256(
            abi.encode(
                kernel.getRecognisedStateTransition(kernel.getRecognisedStateReference(targetId).lastTransitionId)
            )
        );
        uint256 originalTransition = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        requestVm.prank(VERIFIER_ACTOR);
        challenges.resolveChallenge(input);
        require(
            kernel.getRecognisedStateReference(challengeStateId).status
                == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "filed allegation was promoted into the merits finding"
        );
        uint256 acceptedCase = challenges.correctionReviewCaseIdByChallenge(challengeId);
        uint256 findingId = kernel.CORRECTIONS().findingIdByCase(acceptedCase);
        IAVACorrectionReview.RecognisedFinding memory finding = kernel.CORRECTIONS().getFinding(findingId);
        require(findingId != 0 && finding.claimHash == input.finding.claimHash, "limited conclusion missing");
        require(finding.verifier == VERIFIER_ACTOR && finding.evidenceId == filingEvidenceId);
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(originalTransition))) == originalHistory,
            "original recognition history overwritten"
        );
        require(
            challenges.getChallenge(challengeId).decisionEvidenceReceiptId == filingEvidenceId,
            "legacy selected support missing"
        );
    }

    function testChangedOldChallengeStateDoesNotRollbackTargetCorrection() public {
        _screen(challengeId);
        requestVm.prank(VERIFIER_ACTOR);
        kernel.transitionRecognisedState(_transitionInput(challengeStateId, AVACoreTypes.RecognisedStateStatus.Frozen));
        uint256 oldStateTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, filingEvidenceId);
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "target correction rolled back"
        );
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == oldStateTransition,
            "frozen old state changed"
        );
        require(
            challenges.getChallenge(challengeId).challengeStateTransitionIdAfterResolution == oldStateTransition,
            "current old-state history wrong"
        );
    }

    function testNestedPendingChallengeDoesNotRollbackSourceTargetCorrection() public {
        _screen(challengeId);
        uint256 sourceStateTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        (uint256 nestedId, uint256 nestedEvidence, uint256 nestedState) =
            _fileBy(challengeStateId, keccak256("nested.challenge"), DECISION_AUTHOR, DECISION_SUBJECT);
        uint256 nestedHistory = challenges.getChallenge(nestedId).lastTransitionId;
        require(challenges.openChallengeCountByRecognisedState(challengeStateId) == 1, "nested concern not pending");
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, filingEvidenceId);
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "valid target correction rolled back"
        );
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == sourceStateTransition,
            "source challenge state changed"
        );
        AVAChallengeExtension.ChallengeRecord memory source = challenges.getChallenge(challengeId);
        AVAChallengeExtension.ChallengeRecord memory nested = challenges.getChallenge(nestedId);
        require(source.status == AVAChallengeExtension.ChallengeStatus.Resolved, "source resolution missing");
        require(source.outcome == AVAChallengeExtension.ChallengeOutcome.Upheld, "source outcome wrong");
        require(
            nested.status == AVAChallengeExtension.ChallengeStatus.ConcernFiled
                && nested.outcome == AVAChallengeExtension.ChallengeOutcome.None,
            "nested concern resolved implicitly"
        );
        require(nested.lastTransitionId == nestedHistory, "nested history changed");
        require(
            challenges.getChallengeTransition(nestedHistory).evidenceReceiptId == nestedEvidence,
            "nested history unreadable"
        );
        require(
            challenges.getChallengeTransition(filingHistoryId).evidenceReceiptId == filingEvidenceId,
            "source filing lost"
        );
        require(
            challenges.getChallengeTransition(source.lastTransitionId).kind
                == AVAChallengeExtension.ChallengeTransitionKind.Resolution,
            "source resolution unreadable"
        );
        require(
            kernel.getRecognisedStateReference(nestedState).status == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "nested Core state changed"
        );
        require(challenges.openChallengeCountByRecognisedState(challengeStateId) == 1, "nested guard released");
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        kernel.vestRecognisedState(_transitionInput(challengeStateId, AVACoreTypes.RecognisedStateStatus.Vested));
    }

    function testReopenedOldChallengeStillCannotVestAtDifferentTransition() public {
        _screen(challengeId);
        requestVm.startPrank(VERIFIER_ACTOR);
        kernel.transitionRecognisedState(_transitionInput(challengeStateId, AVACoreTypes.RecognisedStateStatus.Frozen));
        kernel.transitionRecognisedState(
            _transitionInput(challengeStateId, AVACoreTypes.RecognisedStateStatus.Challengeable)
        );
        requestVm.stopPrank();
        uint256 oldStateTransition = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, filingEvidenceId);
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == oldStateTransition,
            "advanced old state vested"
        );
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "target correction missing"
        );
    }

    function testInactiveOriginalSubjectNeedsFreshDecisionSupport() public {
        _screen(challengeId);
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, filingEvidenceId);
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, _freshEvidence());
    }

    function testFreshDecisionEvidenceMustRemainActiveForRestoration() public {
        _screen(challengeId);
        uint256 fresh = _freshEvidence();
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
        requestVm.prank(DECISION_AUTHOR);
        evidenceRegistry.recordEvidenceLifecycle(
            fresh,
            ROLE_SOURCE,
            DECISION_SUBJECT,
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("fresh.revoked"),
            "test:revoke"
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.recordRestorationAvailability(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore.available"), "test:restore"
        );
    }

    function testRuleUpgradeAdmitsNewCorrectionSupportAndPreservesFilingAndRestoration() public {
        _screen(challengeId);
        uint256 admissionPackage = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 2);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        requestVm.prank(DECISION_AUTHOR);
        uint256 selected = evidenceRegistry.registerCorrectionEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: DECISION_SUBJECT,
                commitment: keccak256("new.facts.after.upgrade"),
                evidenceTypeHash: keccak256("challenge.support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: DECISION_SUBJECT,
                uri: "test:post-upgrade-decision"
            }),
            admissionPackage,
            keccak256("authorized.historical.reception")
        );
        // A subsequent upgrade must not silently re-label the admission or filing history.
        _registerRequestPackage(new M14PermissiveApplicationModule(APP), 3);
        uint256 resolution = _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, selected);
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(challengeId);
        require(record.packageId == requestPackageId && record.evidenceReceiptId == filingEvidenceId, "filing changed");
        require(record.decisionEvidenceReceiptId == selected, "new support lost");
        require(challenges.getChallengeTransition(filingHistoryId).decisionEvidenceReceiptId == 0, "history rewritten");
        require(challenges.getChallengeTransition(resolution).decisionEvidenceReceiptId == selected, "wrong decision");
        requestVm.prank(VERIFIER_ACTOR);
        challenges.recordRestorationAvailability(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore.available"), "test:restore"
        );
        requestVm.prank(VERIFIER_ACTOR);
        challenges.applyRestoration(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore"), "test:restore"
        );
        AVAGovernanceKernel.RecognisedStateReference memory restored = kernel.getRecognisedStateReference(targetId);
        require(restored.status == AVACoreTypes.RecognisedStateStatus.Restored, "not restored");
        require(
            kernel.getRecognisedStateTransitionReference(restored.lastTransitionId).decisionEvidenceReceiptId
                == selected,
            "restoration support changed"
        );
        (uint256 retainedAdmission,,) = evidenceRegistry.correctionEvidenceAdmissions(selected);
        require(retainedAdmission == admissionPackage, "admission rewritten by upgrade");
    }

    function testFreshDecisionEvidenceCannotComeFromLaterCompatiblePackage() public {
        _screen(challengeId);
        uint256 later = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 2);
        uint256 wrongPackageEvidence =
            _evidence(DECISION_AUTHOR, DECISION_SUBJECT, keccak256("later.support"), later, REQUEST_WORKFLOW);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, wrongPackageEvidence);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, 0);
    }

    function testFreshDecisionEvidenceCannotComeFromAnotherApplication() public {
        _screen(challengeId);
        uint256 foreignReceipt = _foreignEvidence(keccak256("challenge.other.app"), REQUEST_WORKFLOW);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, foreignReceipt);
    }

    function testFreshDecisionEvidenceCannotComeFromAnotherWorkflow() public {
        _screen(challengeId);
        uint256 foreignReceipt = _foreignEvidence(APP, keccak256("challenge.other.workflow"));
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, foreignReceipt);
    }

    function testFreshDecisionEvidenceCannotBeInactive() public {
        _screen(challengeId);
        uint256 fresh = _freshEvidence();
        requestVm.prank(DECISION_AUTHOR);
        evidenceRegistry.recordEvidenceLifecycle(
            fresh,
            ROLE_SOURCE,
            DECISION_SUBJECT,
            AVACoreTypes.EvidenceLifecycleKind.Expire,
            0,
            keccak256("fresh.expired"),
            "test:expire"
        );
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
    }

    function testTargetChangedResidualCanResolveConcernWithoutReversal() public {
        _advanceTargetWithSecondChallenge();
        uint256 targetBefore = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 challengeBefore = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        AVAChallengeExtension.ChallengeResolutionInput memory input =
            _resolution(AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal);
        requestVm.prank(VERIFIER_ACTOR);
        challenges.resolveChallenge(input);
        _assertNoCoreChange(
            AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal,
            filingEvidenceId,
            targetBefore,
            challengeBefore
        );
    }

    function testTargetChangedResidualWithFreshEvidenceCanResolveAfterScreening() public {
        _screen(challengeId);
        _advanceTargetWithSecondChallenge();
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        uint256 fresh = _freshEvidence();
        uint256 targetBefore = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 challengeBefore = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Upheld, fresh);
        _resolve(AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal, fresh);
        _assertNoCoreChange(
            AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal, fresh, targetBefore, challengeBefore
        );
    }

    function testResidualRequiresActualTargetTransitionChangeAndActiveSupport() public {
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal, filingEvidenceId);
        _screen(challengeId);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal, filingEvidenceId);
        _advanceTargetWithSecondChallenge();
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal, 0);
    }

    function testConcernProceduralCloseRemainsClosureWithNone() public {
        requestVm.prank(VERIFIER_ACTOR);
        uint256 transition = challenges.closeChallenge(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("procedural.close"), "test:close"
        );
        AVAChallengeExtension.ChallengeTransitionRecord memory record = challenges.getChallengeTransition(transition);
        require(record.kind == AVAChallengeExtension.ChallengeTransitionKind.Closure, "not procedural closure");
        require(record.outcome == AVAChallengeExtension.ChallengeOutcome.None, "invented resolution");
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "not released");
    }

    function _lostTargetEvidenceBeforeRestoration(AVACoreTypes.EvidenceLifecycleKind kind) private {
        _screen(challengeId);
        _invalidateTargetEvidence(kind);
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, _freshEvidence());
        _expectAvailabilityRevertAndClose();
    }

    function _invalidateTargetEvidence(AVACoreTypes.EvidenceLifecycleKind kind) private {
        AVAGovernanceKernel.RecognisedStateReference memory target = kernel.getRecognisedStateReference(targetId);
        uint256 replacement;
        if (kind == AVACoreTypes.EvidenceLifecycleKind.Supersede) {
            AVACoreTypes.EvidenceRecord memory original = evidenceRegistry.getEvidence(target.evidenceReceiptId);
            requestVm.prank(SOURCE_ACTOR);
            replacement = evidenceRegistry.registerEvidence(
                AVAEvidenceRegistry.EvidenceRegistrationInput({
                    appId: target.appId,
                    workflowKey: target.workflowKey,
                    packageId: target.packageId,
                    roleKey: ROLE_SOURCE,
                    subjectId: target.subjectId,
                    commitment: keccak256("replacement.target.basis"),
                    evidenceTypeHash: original.evidenceTypeHash,
                    disclosurePolicyId: target.disclosurePolicyId,
                    authorityId: target.subjectId,
                    uri: "test:replacement-target-basis"
                })
            );
        }
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            target.evidenceReceiptId,
            ROLE_SOURCE,
            target.subjectId,
            kind,
            replacement,
            keccak256("target.basis.unavailable"),
            "test:target-basis"
        );
    }

    function _makeRestorationAvailable() private {
        _screen(challengeId);
        _resolve(AVAChallengeExtension.ChallengeOutcome.Upheld, _freshEvidence());
        requestVm.prank(VERIFIER_ACTOR);
        challenges.recordRestorationAvailability(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore.available"), "test:restore"
        );
    }

    function _expectAvailabilityRevertAndClose() private {
        uint256 challengeHead = challenges.getChallenge(challengeId).lastTransitionId;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.recordRestorationAvailability(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore.available"), "test:restore"
        );
        require(
            challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.Resolved
                && challenges.getChallenge(challengeId).lastTransitionId == challengeHead,
            "failed availability changed resolution"
        );
        _closeWithoutRestoration();
    }

    function _expectRestorationRevertAndClose() private {
        uint256 challengeHead = challenges.getChallenge(challengeId).lastTransitionId;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.applyRestoration(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("restore"), "test:restore"
        );
        require(
            challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.RestorationAvailable
                && challenges.getChallenge(challengeId).lastTransitionId == challengeHead,
            "failed restoration changed history"
        );
        _closeWithoutRestoration();
    }

    function _closeWithoutRestoration() private {
        uint256 targetHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        requestVm.prank(VERIFIER_ACTOR);
        challenges.closeChallenge(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("close.without.restore"), "test:close"
        );
        require(
            challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.Closed
                && challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.Upheld,
            "resolution lost"
        );
        require(
            kernel.getRecognisedStateReference(targetId).lastTransitionId == targetHead
                && kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "closure restored unavailable target"
        );
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "challenge remains open");
        require(
            challenges.getChallengeTransition(filingHistoryId).kind
                == AVAChallengeExtension.ChallengeTransitionKind.Filing,
            "filing history lost"
        );
    }

    function _unavailableLifecycle(AVACoreTypes.EvidenceLifecycleKind kind, bool screened) private {
        if (screened) _screen(challengeId);
        uint256 replacement = kind == AVACoreTypes.EvidenceLifecycleKind.Supersede
            ? _evidence(CHALLENGER, CHALLENGER_SUBJECT, keccak256("replacement"), requestPackageId, REQUEST_WORKFLOW)
            : 0;
        _invalidateFiling(kind, replacement);
        _resolveUnavailableAndAssert();
    }

    function _resolveUnavailableAndAssert() private {
        uint256 targetBefore = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 challengeBefore = kernel.getRecognisedStateReference(challengeStateId).lastTransitionId;
        _resolve(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
        _assertNoCoreChange(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0, targetBefore, challengeBefore);
        requestVm.prank(VERIFIER_ACTOR);
        challenges.closeChallenge(
            challengeId, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("resolved.close"), "test:close"
        );
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "unavailable stayed open");
    }

    function _assertNoCoreChange(
        AVAChallengeExtension.ChallengeOutcome outcome,
        uint256 selected,
        uint256 targetBefore,
        uint256 challengeBefore
    ) private view {
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(challengeId);
        require(
            record.status == AVAChallengeExtension.ChallengeStatus.Resolved && record.outcome == outcome,
            "resolution missing"
        );
        require(
            record.evidenceReceiptId == filingEvidenceId && record.decisionEvidenceReceiptId == selected,
            "evidence history wrong"
        );
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == targetBefore, "target changed");
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId == challengeBefore,
            "challenge changed"
        );
        AVAChallengeExtension.ChallengeTransitionRecord memory history =
            challenges.getChallengeTransition(record.lastTransitionId);
        require(history.kind == AVAChallengeExtension.ChallengeTransitionKind.Resolution, "not explicit resolution");
        require(
            history.evidenceReceiptId == filingEvidenceId && history.decisionEvidenceReceiptId == selected,
            "resolution history wrong"
        );
        require(challenges.getChallengeTransition(filingHistoryId).decisionEvidenceReceiptId == 0, "filing rewritten");
    }

    function _resolve(AVAChallengeExtension.ChallengeOutcome outcome, uint256 selected) private returns (uint256) {
        AVAChallengeExtension.ChallengeResolutionInput memory input = _resolution(outcome);
        requestVm.prank(VERIFIER_ACTOR);
        return challenges.resolveChallengeWithEvidence(input, selected);
    }

    function _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome outcome, uint256 selected) private {
        AVAChallengeExtension.ChallengeResolutionInput memory input = _resolution(outcome);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(input, selected);
    }

    function _freshEvidence() private returns (uint256) {
        return _evidence(
            DECISION_AUTHOR,
            DECISION_SUBJECT,
            keccak256("fresh.decision"),
            challenges.getChallenge(challengeId).packageId,
            REQUEST_WORKFLOW
        );
    }

    function _foreignEvidence(bytes32 appId, bytes32 workflow) private returns (uint256) {
        bytes32 packageSubject = _authority(ROLE_PACKAGE);
        bytes32 evidenceSubject = DECISION_SUBJECT;
        uint256 policyId = requestPolicyId;
        if (appId != APP) {
            applicationRegistry.registerApplication(
                appId, keccak256("foreign.identity"), keccak256("foreign.authority"), address(this), "test:foreign"
            );
            packageSubject = keccak256("foreign.package-subject");
            evidenceSubject = keccak256("foreign.evidence-subject");
            identityRegistry.assignSubject(address(this), appId, ROLE_PACKAGE, packageSubject, "test:foreign-package");
            identityRegistry.assignSubject(DECISION_AUTHOR, appId, ROLE_SOURCE, evidenceSubject, "test:foreign-source");
            authorityMatrix.setPermission(appId, ROLE_PACKAGE, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, true);
            authorityMatrix.setPermission(appId, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
            authorityMatrix.setPermission(appId, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_DISCLOSURE_POLICY, true);
            requestVm.prank(DECISION_AUTHOR);
            policyId = disclosureRegistry.registerPolicy(
                appId, ROLE_SOURCE, evidenceSubject, keccak256("foreign.policy"), "Foreign", "test:foreign-policy"
            );
        }
        uint256 packageId = packageRegistry.registerRulePackage(
            _corePackageInput(
                appId,
                workflow,
                ROLE_PACKAGE,
                packageSubject,
                1,
                keccak256("request.compatibility"),
                "test:foreign-package"
            ),
            _coreBindings(new M14PermissiveApplicationModule(appId))
        );
        requestVm.prank(DECISION_AUTHOR);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: appId,
                workflowKey: workflow,
                packageId: packageId,
                roleKey: ROLE_SOURCE,
                subjectId: evidenceSubject,
                commitment: keccak256("foreign.receipt"),
                evidenceTypeHash: keccak256("challenge.support"),
                disclosurePolicyId: policyId,
                authorityId: evidenceSubject,
                uri: "test:foreign-receipt"
            })
        );
    }

    function _advanceTargetWithSecondChallenge() private {
        (uint256 second,,) = _fileBy(targetId, keccak256("second.challenge"), DECISION_AUTHOR, DECISION_SUBJECT);
        _screen(second);
        AVAChallengeExtension.ChallengeResolutionInput memory input =
            _resolution(AVAChallengeExtension.ChallengeOutcome.Upheld);
        input.challengeId = second;
        requestVm.prank(VERIFIER_ACTOR);
        challenges.resolveChallenge(input);
    }

    function _policyRejection(uint8 policyKind) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(new M14PermissiveApplicationModule(APP));
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            new AVACoreRulePackageRegistry.ModuleBinding[](base.length + (policyKind == 2 ? 1 : 0));
        for (uint256 i; i < base.length; ++i) {
            bindings[i] = base[i];
        }
        address policy = address(new ChallengeResolutionRejectPolicy());
        if (policyKind == 0) bindings[6] = _coreBinding(AVACapabilityKeys.CHALLENGE_POLICY, policy);
        else if (policyKind == 1) bindings[7] = _coreBinding(AVACapabilityKeys.AUTHORITY_POLICY, policy);
        else bindings[base.length] = _coreBinding(AVACapabilityKeys.ANTI_ABUSE, policy);
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:reject-policy"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        targetId = _createStateForCommitment(keccak256(abi.encode("policy.target", policyKind)));
        (challengeId, filingEvidenceId, challengeStateId) = _file(targetId, keccak256("policy.challenge"));
        filingHistoryId = challenges.getChallenge(challengeId).lastTransitionId;
        _screen(challengeId);
        _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind.Revoke, 0);
        _registerRequestPackage(new M14PermissiveApplicationModule(APP), 3);
        _expectResolutionRevert(AVAChallengeExtension.ChallengeOutcome.Unavailable, 0);
        require(
            challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.AdmissibilityScreening,
            "policy rejection bypassed"
        );
    }

    function _resolution(AVAChallengeExtension.ChallengeOutcome outcome)
        private
        view
        returns (AVAChallengeExtension.ChallengeResolutionInput memory)
    {
        return AVAChallengeExtension.ChallengeResolutionInput({
            challengeId: challengeId,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            outcome: outcome,
            correctionStatus: outcome == AVAChallengeExtension.ChallengeOutcome.Upheld
                ? AVACoreTypes.RecognisedStateStatus.Voided
                : kernel.getRecognisedStateReference(targetId).status,
            reasonHash: keccak256(abi.encode("resolution", challengeId, outcome)),
            reasonURI: "test:resolution",
            finding: _findingInput(
                outcome != AVAChallengeExtension.ChallengeOutcome.Unavailable
                    && outcome != AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal
            )
        });
    }

    function _invalidateFiling(AVACoreTypes.EvidenceLifecycleKind kind, uint256 replacement) private {
        requestVm.prank(CHALLENGER);
        evidenceRegistry.recordEvidenceLifecycle(
            filingEvidenceId,
            ROLE_SOURCE,
            CHALLENGER_SUBJECT,
            kind,
            replacement,
            keccak256(abi.encode("invalidate", kind)),
            "test:invalidate"
        );
    }

    function _file(uint256 targetStateId, bytes32 seed)
        private
        returns (uint256 id, uint256 evidenceId, uint256 stateId)
    {
        return _fileBy(targetStateId, seed, CHALLENGER, CHALLENGER_SUBJECT);
    }

    function _fileBy(uint256 targetStateId, bytes32 seed, address challenger, bytes32 subject)
        private
        returns (uint256 id, uint256 evidenceId, uint256 stateId)
    {
        evidenceId = _evidence(challenger, subject, seed, requestPackageId, REQUEST_WORKFLOW);
        requestVm.startPrank(challenger);
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: keccak256("challenge.test.concern"),
                objectCommitment: seed,
                parentObjectId: kernel.getRecognisedStateReference(targetStateId).governedObjectId,
                subjectId: subject,
                evidenceReceiptId: evidenceId,
                disclosurePolicyId: requestPolicyId,
                metadataHash: seed,
                authorityId: subject,
                uri: "test:concern"
            })
        );
        stateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_SOURCE,
                authorityId: subject,
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Registered,
                reasonHash: seed,
                reasonURI: "test:concern-state"
            })
        );
        id = challenges.fileChallenge(
            AVAChallengeExtension.ChallengeFilingInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                challengeRecognisedStateId: stateId,
                challengedRecognisedStateId: targetStateId,
                roleKey: ROLE_SOURCE,
                reasonHash: seed,
                reasonURI: "test:filing"
            })
        );
        requestVm.stopPrank();
    }

    function _evidence(address actor, bytes32 subject, bytes32 seed, uint256 packageId, bytes32 workflow)
        private
        returns (uint256)
    {
        requestVm.prank(actor);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: workflow,
                packageId: packageId,
                roleKey: ROLE_SOURCE,
                subjectId: subject,
                commitment: keccak256(abi.encode("challenge.evidence", seed)),
                evidenceTypeHash: keccak256("challenge.support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: subject,
                uri: "test:evidence"
            })
        );
    }

    function _screen(uint256 id) private {
        requestVm.prank(VERIFIER_ACTOR);
        challenges.screenChallenge(id, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
    }
}
