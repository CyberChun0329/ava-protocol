// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAAntiAbusePolicyModule,
    IAVAEvidencePolicyModule
} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVAChallengeExtension} from "../src/extensions/challenge/AVAChallengeExtension.sol";
import {AVAChallengePolicyValidation} from "../src/extensions/challenge/AVAChallengePolicyValidation.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface CoreCorrectionReviewVm {
    function expectRevert(bytes calldata revertData) external;
}

/// @notice Intake succeeds, but every ordinary resolution and ordinary review-evidence admission is vetoed.
contract CoreReviewOrdinaryVetoPolicy is
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAAntiAbusePolicyModule,
    IAVAEvidencePolicyModule,
    RuleModuleIdentity
{
    error OrdinaryResolutionVeto();
    error OrdinaryEvidenceVeto();

    bool private identityInvalidated;

    function validateChallenge(ChallengeContext calldata context) external pure {
        if (context.actionKey == AVACoreTypes.ACTION_RESOLVE_CHALLENGE) revert OrdinaryResolutionVeto();
    }

    function validateAuthority(AuthorityContext calldata context) external pure {
        if (context.actionKey == AVACoreTypes.ACTION_RESOLVE_CHALLENGE) revert OrdinaryResolutionVeto();
    }

    function validateAntiAbuse(AntiAbuseContext calldata context) external pure {
        if (context.actionKey == AVACoreTypes.ACTION_RESOLVE_CHALLENGE) revert OrdinaryResolutionVeto();
    }

    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata context) external pure {
        if (context.evidenceTypeHash == keccak256("core.review.support")) revert OrdinaryEvidenceVeto();
    }

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata) external pure {}

    /// @notice Simulates loss of the historical package's pinned module identity through a public module API.
    function invalidatePinnedIdentity() external {
        identityInvalidated = true;
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return identityInvalidated ? keccak256("invalidated") : bytes32(0);
    }
}

/// @notice Models an origin whose final application fails after Core review validation.
contract RevertingCorrectionOrigin {
    error ApplicationFailed();
    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;

    constructor(AVAGovernanceKernel host) {
        GOVERNANCE_KERNEL = host;
    }

    function accept(IAVACorrectionReview.CaseInput calldata input) external returns (uint256) {
        return GOVERNANCE_KERNEL.CORRECTIONS().registerCase(input);
    }

    function correctionTargetVersion(uint256) external pure returns (uint256) {
        return 0;
    }

    function applyCorrectionReview(uint256) external pure {
        revert ApplicationFailed();
    }

    function forgeFinding(IAVACorrectionReview.FindingFormation calldata input) external returns (uint256) {
        return GOVERNANCE_KERNEL.CORRECTIONS().recordFinding(input);
    }
}

/// @notice A small atomic effect used after rejected correction-intake attempts.
contract CorrectionAdmissionExecutor {
    uint256 public effects;

    function execute(AVARequestAllocation allocation, uint256 id, bytes32 response, bytes32 parameters) external {
        allocation.consume(id, response, parameters, msg.sender);
        ++effects;
        allocation.complete(id, keccak256(abi.encode("admission.effect", effects)));
    }
}

/// @notice Loses future intake eligibility through a public API, while retaining its accepted-case callback.
contract RetainedCorrectionOrigin {
    AVAGovernanceKernel public GOVERNANCE_KERNEL;
    IAVACorrectionReview private immutable retainedRegistry;
    uint256 public appliedReviewId;

    constructor(AVAGovernanceKernel host) {
        GOVERNANCE_KERNEL = host;
        retainedRegistry = host.CORRECTIONS();
    }

    function invalidateAdmissionHost() external {
        GOVERNANCE_KERNEL = AVAGovernanceKernel(address(0xBAD));
    }

    function accept(IAVACorrectionReview.CaseInput calldata input) external returns (uint256) {
        return retainedRegistry.registerCase(input);
    }

    function correctionTargetVersion(uint256) external pure returns (uint256) {
        return 0;
    }

    function applyCorrectionReview(uint256 id) external {
        require(msg.sender == address(retainedRegistry) && retainedRegistry.activeReviewId() == id);
        retainedRegistry.activeDisposition(id);
        appliedReviewId = id;
    }
}

/// @notice Public deployed-Core lifecycle tests; no storage or code mutation cheatcodes.
contract CoreCorrectionReviewTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("core.correction.review.app");
    bytes32 private constant ROLE_REVIEW = keccak256("core.correction.review.role");
    bytes32 private constant REVIEW_SUBJECT = keccak256("core.correction.review.subject");
    bytes32 private constant CHALLENGER_SUBJECT = keccak256("core.correction.challenger.subject");
    bytes32 private constant SECOND_CHALLENGER_SUBJECT = keccak256("core.correction.second.challenger");
    bytes32 private constant REVIEW_SUPPORT = keccak256("core.review.support");
    address private constant REVIEWER = address(0xC5);
    address private constant CHALLENGER = address(0xC3);
    address private constant SECOND_CHALLENGER = address(0xC4);

    AVAChallengeExtension private challenges;
    IAVACorrectionReview private corrections;
    CoreReviewOrdinaryVetoPolicy private vetoPolicy;
    uint256 private targetId;
    uint256 private challengeId;
    uint256 private filingEvidenceId;
    uint256 private challengeStateId;
    uint256 private caseId;
    uint256 private filingHistoryId;

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("core.review.target"));
        identityRegistry.assignSubject(CHALLENGER, APP, ROLE_SOURCE, CHALLENGER_SUBJECT, "test:challenger");
        identityRegistry.assignSubject(
            SECOND_CHALLENGER, APP, ROLE_SOURCE, SECOND_CHALLENGER_SUBJECT, "test:second-challenger"
        );
        identityRegistry.assignSubject(REVIEWER, APP, ROLE_REVIEW, REVIEW_SUBJECT, "test:independent-reviewer");
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FILE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_SCREEN_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_CLOSE_CHALLENGE, true);
        challenges =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
        corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        _installVetoPackage();
        targetId = _createStateForCommitment(keccak256("core.review.source"));
        (challengeId, filingEvidenceId, challengeStateId) =
            _file(targetId, keccak256("core.review.challenge"), CHALLENGER, CHALLENGER_SUBJECT);
        filingHistoryId = challenges.getChallenge(challengeId).lastTransitionId;
        _screen(challengeId);
        caseId = challenges.correctionReviewCaseIdByChallenge(challengeId);
    }

    function testScreeningRegistersAcceptedSourceCaseWithHistoricalLineage() public view {
        IAVACorrectionReview.CaseRecord memory item = corrections.getCase(caseId);
        AVAChallengeExtension.ChallengeRecord memory challenge = challenges.getChallenge(challengeId);
        require(item.id != 0 && item.origin == address(challenges), "accepted case missing");
        require(item.input.kind == IAVACorrectionReview.TargetKind.Source, "wrong target kind");
        require(item.input.originCaseId == challengeId && item.input.targetId == targetId, "wrong origin");
        require(item.input.originalTargetVersion == challenge.targetTransitionIdAtFiling, "head not retained");
        require(item.input.filingEvidenceId == filingEvidenceId && item.reviewId == 0, "filing rewritten");
        require(item.input.originalActor == VERIFIER_ACTOR && item.input.affectedActor == SOURCE_ACTOR, "actors lost");
        require(item.input.challenger == CHALLENGER && challenges.openChallengeCountByRecognisedState(targetId) == 1);
    }

    function testIndependentWithdrawalSurvivesOrdinaryVetoAndHistoricalInputLoss() public {
        AVAChallengeExtension.ChallengeRecord memory beforeChallenge = challenges.getChallenge(challengeId);
        AVAGovernanceKernel.RecognisedStateReference memory beforeTarget = kernel.getRecognisedStateReference(targetId);
        bytes32 targetHistoryHash =
            keccak256(abi.encode(kernel.getRecognisedStateTransition(beforeTarget.lastTransitionId)));
        bytes32 filingHistoryHash = keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId)));
        AVAChallengeExtension.ChallengeResolutionInput memory ordinary =
            _ordinaryResolution(challengeId, AVAChallengeExtension.ChallengeOutcome.Upheld);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert(CoreReviewOrdinaryVetoPolicy.OrdinaryResolutionVeto.selector);
        challenges.resolveChallenge(ordinary);

        requestVm.warp(block.timestamp + 365 days);
        _expireEvidence(filingEvidenceId, CHALLENGER, CHALLENGER_SUBJECT);
        _expireEvidence(beforeTarget.evidenceReceiptId, SOURCE_ACTOR, _authority(ROLE_SOURCE));
        ordinary = _ordinaryResolution(challengeId, AVAChallengeExtension.ChallengeOutcome.Unavailable);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert(CoreReviewOrdinaryVetoPolicy.OrdinaryResolutionVeto.selector);
        challenges.resolveChallenge(ordinary);
        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_VERIFIER));
        vetoPolicy.invalidatePinnedIdentity();

        uint256 support = _reviewEvidence(caseId);
        uint256 reviewId = _review(caseId, IAVACorrectionReview.Outcome.Withdrawn, support);
        AVAGovernanceKernel.RecognisedStateReference memory afterTarget = kernel.getRecognisedStateReference(targetId);
        AVACoreTypes.RecognisedStateTransitionRecord memory repair =
            kernel.getRecognisedStateTransition(afterTarget.lastTransitionId);
        require(afterTarget.status == AVACoreTypes.RecognisedStateStatus.Voided, "source not withdrawn");
        require(afterTarget.lastTransitionId != beforeTarget.lastTransitionId, "no append-only repair");
        require(repair.kind == AVACoreTypes.TransitionKind.AuthorisedRepair, "not independent repair");
        require(repair.sourceRecordId == reviewId && repair.decisionEvidenceReceiptId == support, "review lineage lost");
        require(repair.createdBy == REVIEWER && repair.authorityId == REVIEW_SUBJECT, "review authority lost");
        require(repair.evidenceReceiptId == beforeTarget.evidenceReceiptId, "source evidence replaced");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(beforeTarget.lastTransitionId)))
                == targetHistoryHash,
            "original source history rewritten"
        );
        require(
            keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId))) == filingHistoryHash,
            "filing history rewritten"
        );
        require(evidenceRegistry.getEvidenceReference(filingEvidenceId).status == AVACoreTypes.EvidenceStatus.Expired);
        require(afterTarget.evidenceReceiptId == beforeTarget.evidenceReceiptId, "original evidence removed");
        _assertClosedWithoutChallengeVesting(beforeChallenge, support);
        require(challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.Upheld);
        require(
            corrections.getCase(caseId).reviewId == reviewId && corrections.activeReviewId() == 0, "review not final"
        );
    }

    function testAffirmationClosesCaseWithoutVestingChallengeOrChangingSource() public {
        _assertNonReversingReview(IAVACorrectionReview.Outcome.Affirmed);
        require(challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.ReviewAffirmed);
    }

    function testAcceptedCaseRetainsIndependentReviewWithoutOrdinaryValidationLibrary() public {
        requestVm.etch(address(AVAChallengePolicyValidation), hex"");
        _assertNonReversingReview(IAVACorrectionReview.Outcome.Affirmed);
        require(corrections.findingIdByCase(caseId) != 0, "independent recognised finding missing");
    }

    function testFormalReviewFormsFindingWithoutSeparateRecognitionWorkflow() public {
        uint256 support = _reviewEvidence(caseId);
        IAVACorrectionReview.ReviewInput memory input =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.Affirmed, support);
        input.finding.claimHash = keccak256("review confirms the original completion finding remains supported");
        input.finding.useScopeHash = keccak256("this source-completion dispute only");
        uint256 businessStateCounter = kernel.nextRecognisedStateId();
        requestVm.prank(REVIEWER);
        uint256 reviewId = corrections.review(input);
        uint256 findingId = corrections.findingIdByCase(caseId);
        IAVACorrectionReview.RecognisedFinding memory finding = corrections.getFinding(findingId);
        require(findingId != 0 && finding.caseId == caseId, "formal review finding missing");
        require(finding.claimHash == input.finding.claimHash && finding.useScopeHash == input.finding.useScopeHash);
        require(finding.burdenHash == input.finding.burdenHash && finding.evidenceId == support);
        require(finding.verifier == REVIEWER && finding.verifierAuthorityId == REVIEW_SUBJECT);
        require(finding.independentReview && finding.formationAction == AVACoreTypes.ACTION_REVIEW_CORRECTION);
        require(
            corrections.getReview(reviewId).input.finding.claimHash == finding.claimHash, "verification provenance lost"
        );
        require(kernel.nextRecognisedStateId() == businessStateCounter, "business state fabricated");
    }

    function testUsableFindingReferenceRetainsEstablishedReuseRulesAndRejectsExpiredEvidence() public {
        uint256 support = _reviewEvidence(caseId);
        _review(caseId, IAVACorrectionReview.Outcome.Affirmed, support);
        uint256 id = corrections.findingIdByCase(caseId);
        bytes32 recorded = keccak256(abi.encode(corrections.getFinding(id)));
        require(
            keccak256(abi.encode(corrections.requireUsableFindingReference(id))) == recorded, "exact usable finding"
        );
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REVIEW_CORRECTION, false);
        require(corrections.requireUsableFindingReference(id).id == id, "historical authority is not reauthorised");
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE, true);
        requestVm.prank(REVIEWER);
        evidenceRegistry.recordEvidenceLifecycle(
            support,
            ROLE_REVIEW,
            REVIEW_SUBJECT,
            AVACoreTypes.EvidenceLifecycleKind.Expire,
            0,
            keccak256("expire finding evidence"),
            "test:expire-finding"
        );
        requestVm.expectRevert();
        corrections.requireUsableFindingReference(id);
        require(keccak256(abi.encode(corrections.getFinding(id))) == recorded, "eligibility loss preserves record");
    }

    function testAvailableReviewEvidenceWithoutAcceptedClaimCannotFormFinding() public {
        uint256 support = _reviewEvidence(caseId);
        IAVACorrectionReview.ReviewInput memory input =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.Affirmed, support);
        input.finding.claimHash = bytes32(0);
        _expectReviewRevert(input);
        require(corrections.findingIdByCase(caseId) == 0 && corrections.getCase(caseId).reviewId == 0);
    }

    function testNeutralClosureCannotSmuggleSubstantiveFinding() public {
        _expireEvidence(filingEvidenceId, CHALLENGER, CHALLENGER_SUBJECT);
        IAVACorrectionReview.ReviewInput memory input =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.EvidenceUnavailable, 0);
        input.finding = _findingInput(true);
        _expectReviewRevert(input);
        require(corrections.findingIdByCase(caseId) == 0, "neutral produced an adverse finding");
        input.finding = _findingInput(false);
        requestVm.prank(REVIEWER);
        corrections.review(input);
        require(corrections.findingIdByCase(caseId) == 0, "neutral required substantive recognition");
    }

    function testLaterFindingSupersedesWithoutRewritingOldFindingOrAllowingItsReuse() public {
        _review(caseId, IAVACorrectionReview.Outcome.Affirmed, _reviewEvidence(caseId));
        uint256 first = corrections.findingIdByCase(caseId);
        bytes32 beforeFinding = keccak256(abi.encode(corrections.getFinding(first)));
        (uint256 nextChallenge,,) =
            _file(targetId, keccak256("later merits"), SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT);
        _screen(nextChallenge);
        uint256 nextCase = challenges.correctionReviewCaseIdByChallenge(nextChallenge);
        IAVACorrectionReview.ReviewInput memory input =
            _reviewInput(nextCase, IAVACorrectionReview.Outcome.Affirmed, _reviewEvidence(nextCase));
        input.finding.supersedesFindingId = first;
        input.finding.claimHash = keccak256("later review narrows the earlier finding within its declared use");
        requestVm.prank(REVIEWER);
        corrections.review(input);
        uint256 successor = corrections.findingIdByCase(nextCase);
        require(successor > first && corrections.supersededByFindingId(first) == successor, "no finding succession");
        requestVm.expectRevert();
        corrections.requireUsableFindingReference(first);
        require(corrections.requireUsableFindingReference(successor).id == successor, "usable successor");
        require(corrections.getFinding(successor).supersedesFindingId == first);
        require(keccak256(abi.encode(corrections.getFinding(first))) == beforeFinding, "prior finding rewritten");
        address thirdActor = address(0xC6);
        bytes32 thirdSubject = keccak256("third distinct challenger");
        identityRegistry.assignSubject(thirdActor, APP, ROLE_SOURCE, thirdSubject, "test:third-challenger");
        (uint256 thirdChallenge,,) = _file(targetId, keccak256("third merits"), thirdActor, thirdSubject);
        _screen(thirdChallenge);
        uint256 thirdCase = challenges.correctionReviewCaseIdByChallenge(thirdChallenge);
        input = _reviewInput(thirdCase, IAVACorrectionReview.Outcome.Affirmed, _reviewEvidence(thirdCase));
        input.finding.existingFindingId = first;
        _expectReviewRevert(input);
        require(corrections.findingIdByCase(thirdCase) == 0, "superseded finding reused");
    }

    function testApplicationFailureRollsBackFindingAndReviewTogether() public {
        RevertingCorrectionOrigin origin = new RevertingCorrectionOrigin(kernel);
        corrections.bindRequestOrigin(APP, address(origin));
        IAVACorrectionReview.CaseInput memory accepted = corrections.getCase(caseId).input;
        accepted.kind = IAVACorrectionReview.TargetKind.Allocation;
        accepted.originCaseId = 77;
        accepted.targetId = 77;
        accepted.originalTargetVersion = 0;
        uint256 failedCase = origin.accept(accepted);
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = failedCase;
        input.outcome = IAVACorrectionReview.Outcome.Affirmed;
        input.evidenceId = _reviewEvidence(failedCase);
        input.roleKey = ROLE_REVIEW;
        input.authorityId = REVIEW_SUBJECT;
        input.reasonHash = keccak256("independent merits finding before failed application");
        input.finding = _findingInput(true);
        uint256 beforeCounter = kernel.CORRECTIONS().nextFindingId();
        requestVm.prank(REVIEWER);
        requestVm.expectRevert(RevertingCorrectionOrigin.ApplicationFailed.selector);
        corrections.review(input);
        require(kernel.CORRECTIONS().nextFindingId() == beforeCounter, "orphan finding remained");
        require(corrections.findingIdByCase(failedCase) == 0 && corrections.getCase(failedCase).reviewId == 0);
        require(corrections.activeReviewId() == 0, "active review leaked");
    }

    function testUnboundOriginCannotAttributeFindingToAnExistingCase() public {
        RevertingCorrectionOrigin origin = new RevertingCorrectionOrigin(kernel);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, keccak256("ava.extension.request.challenge.resolve.v1"), true);
        IAVACorrectionReview.FindingFormation memory input = IAVACorrectionReview.FindingFormation({
            caseId: caseId,
            targetVersion: corrections.getCase(caseId).input.originalTargetVersion,
            evidenceId: filingEvidenceId,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            verifier: VERIFIER_ACTOR,
            substantive: true,
            finding: _findingInput(true)
        });
        requestVm.expectRevert();
        origin.forgeFinding(input);
        require(corrections.findingIdByCase(caseId) == 0, "forged verifier attributed a finding");
    }

    function testUntrustedAllocationOriginsRejectThenLegitimateReviewAndExecutionComplete() public {
        _assertOriginAdmissionThenLegitimateReview(AVARequestAllocation.ChallengeTarget.Allocation);
    }

    function testUntrustedEffectOriginsRejectThenLegitimateReviewRetainsExecution() public {
        _assertOriginAdmissionThenLegitimateReview(AVARequestAllocation.ChallengeTarget.Effect);
    }

    function _assertOriginAdmissionThenLegitimateReview(AVARequestAllocation.ChallengeTarget kind) private {
        uint256 previousReview = _review(caseId, IAVACorrectionReview.Outcome.Affirmed, _reviewEvidence(caseId));
        uint256 previousFinding = corrections.findingIdByCase(caseId);
        bytes32 previousHistory = keccak256(
            abi.encode(
                corrections.getCase(caseId),
                corrections.getReview(previousReview),
                corrections.getFinding(previousFinding)
            )
        );
        RevertingCorrectionOrigin origin = new RevertingCorrectionOrigin(kernel);
        IAVACorrectionReview.CaseInput memory forged = corrections.getCase(caseId).input;
        forged.kind = kind == AVARequestAllocation.ChallengeTarget.Allocation
            ? IAVACorrectionReview.TargetKind.Allocation
            : IAVACorrectionReview.TargetKind.Effect;
        forged.originCaseId = 78;
        forged.targetId = 78;
        forged.originalTargetVersion = 0;
        uint256 nextCase = kernel.CORRECTIONS().nextCaseId();
        bytes32 originKey = keccak256(abi.encode(address(origin), forged.kind, forged.originCaseId));
        requestVm.expectRevert();
        origin.accept(forged);
        require(kernel.CORRECTIONS().nextCaseId() == nextCase, "unbound intake advanced case counter");
        require(kernel.CORRECTIONS().caseIdByOrigin(originKey) == 0, "unbound intake reserved origin case");

        bytes32 otherApp = keccak256("other.correction.origin.app");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other.namespace"), keccak256("other.authority"), address(this), "test:other-app"
        );
        corrections.bindRequestOrigin(otherApp, address(origin));
        requestVm.expectRevert();
        origin.accept(forged);
        require(kernel.CORRECTIONS().nextCaseId() == nextCase, "other app binding admitted case");
        require(kernel.CORRECTIONS().caseIdByOrigin(originKey) == 0, "other app intake reserved origin case");

        CorrectionAdmissionExecutor executor = new CorrectionAdmissionExecutor();
        bytes32 response = keccak256("admission.response");
        bytes32 parameters = keccak256("admission.parameters");
        bytes32 burden = keccak256("admission.burden");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 source = _createRequestState(address(executor), response, parameters, burden, expiry);
        bytes32 sourceHistory = keccak256(abi.encode(kernel.getRecognisedStateReference(source)));
        uint256 requestId = _createRequest(
            AVARequestAllocation.RequestInput(source, address(executor), response, parameters, burden, expiry)
        );
        _approveRequest(requestId);
        if (kind == AVARequestAllocation.ChallengeTarget.Effect) {
            executor.execute(requestAllocation, requestId, response, parameters);
        }
        bytes32 requestHistory = keccak256(abi.encode(requestAllocation.getRequest(requestId)));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, keccak256("ava.extension.request.challenge.file.v1"), true);
        requestVm.prank(CHALLENGER);
        uint256 requestChallenge = requestAllocation.fileRequestChallenge(
            requestId, kind, filingEvidenceId, ROLE_SOURCE, CHALLENGER_SUBJECT, keccak256("valid request challenge")
        );
        uint256 acceptedCase = requestAllocation.correctionReviewCaseIdByChallenge(requestChallenge);
        require(acceptedCase == nextCase && corrections.getCase(acceptedCase).origin == address(requestAllocation));
        IAVACorrectionReview.ReviewInput memory input = _requestOriginReviewInput(acceptedCase);
        requestVm.prank(REVIEWER);
        uint256 reviewId = corrections.review(input);
        require(corrections.getCase(acceptedCase).reviewId == reviewId, "legitimate review incomplete");
        require(corrections.findingIdByCase(acceptedCase) != 0, "limited finding missing");
        require(
            requestAllocation.getRequestChallenge(requestChallenge).outcome
                == AVARequestAllocation.ResolutionOutcome.Rejected
        );
        require(
            keccak256(abi.encode(requestAllocation.getRequest(requestId))) == requestHistory,
            "review rewrote allocation or effect"
        );
        if (kind == AVARequestAllocation.ChallengeTarget.Allocation) {
            executor.execute(requestAllocation, requestId, response, parameters);
        }
        requestVm.expectRevert();
        executor.execute(requestAllocation, requestId, response, parameters);
        require(executor.effects() == 1 && requestAllocation.getRequest(requestId).completed, "effect not once-only");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateReference(source))) == sourceHistory, "recognition rewritten"
        );
        require(
            previousHistory
                == keccak256(
                    abi.encode(
                        corrections.getCase(caseId),
                        corrections.getReview(previousReview),
                        corrections.getFinding(previousFinding)
                    )
                ),
            "earlier correction history rewritten"
        );
    }

    function _requestOriginReviewInput(uint256 id) private returns (IAVACorrectionReview.ReviewInput memory input) {
        input.caseId = id;
        input.expectedTargetVersion = corrections.getCase(id).input.originalTargetVersion;
        input.outcome = IAVACorrectionReview.Outcome.Affirmed;
        input.evidenceId = _reviewEvidence(id);
        input.roleKey = ROLE_REVIEW;
        input.authorityId = REVIEW_SUBJECT;
        input.reasonHash = keccak256("independent request finding");
        input.finding = _findingInput(true);
    }

    function testAcceptedCaseRetainsReviewAfterFutureAdmissionEligibilityIsLost() public {
        RetainedCorrectionOrigin origin = new RetainedCorrectionOrigin(kernel);
        corrections.bindRequestOrigin(APP, address(origin));
        IAVACorrectionReview.CaseInput memory accepted = corrections.getCase(caseId).input;
        accepted.kind = IAVACorrectionReview.TargetKind.Allocation;
        accepted.originCaseId = 79;
        accepted.targetId = 79;
        accepted.originalTargetVersion = 0;
        uint256 retainedCase = origin.accept(accepted);
        bytes32 acceptedHistory = keccak256(abi.encode(corrections.getCase(retainedCase).input));
        uint256 businessCounter = kernel.nextRecognisedStateId();
        origin.invalidateAdmissionHost();
        bytes32 pin = corrections.requestOriginCodeHash(APP, address(origin));
        corrections.setRequestOriginEnabled(APP, address(origin), false);
        require(corrections.requestOriginDisabled(APP, address(origin)), "drifted origin could not be retired");
        requestVm.expectRevert();
        corrections.setRequestOriginEnabled(APP, address(origin), true);
        require(corrections.requestOriginCodeHash(APP, address(origin)) == pin, "retirement removed code pin");
        accepted.originCaseId = 80;
        uint256 nextCase = kernel.CORRECTIONS().nextCaseId();
        requestVm.expectRevert();
        origin.accept(accepted);
        require(kernel.CORRECTIONS().nextCaseId() == nextCase, "ineligible intake changed counter");

        IAVACorrectionReview.ReviewInput memory input = _requestOriginReviewInput(retainedCase);
        requestVm.prank(REVIEWER);
        uint256 reviewId = corrections.review(input);
        require(origin.appliedReviewId() == reviewId && corrections.getCase(retainedCase).reviewId == reviewId);
        uint256 findingId = corrections.findingIdByCase(retainedCase);
        require(corrections.getFinding(findingId).independentReview, "retained review did not form conclusion");
        require(
            keccak256(abi.encode(corrections.getCase(retainedCase).input)) == acceptedHistory,
            "accepted identity changed"
        );
        require(kernel.nextRecognisedStateId() == businessCounter, "business recognition fabricated");
        require(corrections.activeReviewId() == 0, "retained callback leaked context");
    }

    function testDisabledAllocationOriginRetainsReviewAndRequiresExplicitReactivationForIntake() public {
        _assertRetiredOriginLifecycle(AVARequestAllocation.ChallengeTarget.Allocation);
    }

    function testDisabledEffectOriginRetainsReviewAndHistoryBeforeExplicitReactivation() public {
        _assertRetiredOriginLifecycle(AVARequestAllocation.ChallengeTarget.Effect);
    }

    function _assertRetiredOriginLifecycle(AVARequestAllocation.ChallengeTarget kind) private {
        uint256 priorReview = _review(caseId, IAVACorrectionReview.Outcome.Affirmed, _reviewEvidence(caseId));
        uint256 priorFinding = corrections.findingIdByCase(caseId);
        bytes32 priorHistory = keccak256(
            abi.encode(
                corrections.getCase(caseId), corrections.getReview(priorReview), corrections.getFinding(priorFinding)
            )
        );
        CorrectionAdmissionExecutor executor = new CorrectionAdmissionExecutor();
        bytes32 response = keccak256("retirement.response");
        bytes32 parameters = keccak256("retirement.parameters");
        bytes32 burden = keccak256("retirement.burden");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 source = _createRequestState(address(executor), response, parameters, burden, expiry);
        uint256 requestId = _createRequest(
            AVARequestAllocation.RequestInput(source, address(executor), response, parameters, burden, expiry)
        );
        _approveRequest(requestId);
        if (kind == AVARequestAllocation.ChallengeTarget.Effect) {
            executor.execute(requestAllocation, requestId, response, parameters);
        }
        bytes32 requestHistory = keccak256(abi.encode(requestAllocation.getRequest(requestId)));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        uint256 requestChallenge =
            _fileRetirementChallenge(requestId, kind, CHALLENGER, CHALLENGER_SUBJECT, filingEvidenceId);
        uint256 acceptedCase = requestAllocation.correctionReviewCaseIdByChallenge(requestChallenge);
        bytes32 acceptedHistory = keccak256(abi.encode(corrections.getCase(acceptedCase).input));
        require(!corrections.requestOriginDisabled(APP, address(requestAllocation)), "bound origin started disabled");
        bytes32 pin = corrections.requestOriginCodeHash(APP, address(requestAllocation));
        corrections.setRequestOriginEnabled(APP, address(requestAllocation), false);
        corrections.bindRequestOrigin(APP, address(requestAllocation));
        require(corrections.requestOriginDisabled(APP, address(requestAllocation)), "repeat binding revived origin");
        require(corrections.requestOriginCodeHash(APP, address(requestAllocation)) == pin, "retirement changed pin");

        uint256 secondEvidence = _secondRequestFilingEvidence();
        uint256 nextCase = kernel.CORRECTIONS().nextCaseId();
        uint256 nextOriginCase = requestAllocation.nextRequestChallengeId();
        IAVACorrectionReview.TargetKind coreKind = kind == AVARequestAllocation.ChallengeTarget.Allocation
            ? IAVACorrectionReview.TargetKind.Allocation
            : IAVACorrectionReview.TargetKind.Effect;
        bytes32 originKey = keccak256(abi.encode(address(requestAllocation), coreKind, nextOriginCase));
        requestVm.expectRevert();
        _fileRetirementChallenge(requestId, kind, SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT, secondEvidence);
        require(kernel.CORRECTIONS().nextCaseId() == nextCase, "retired intake advanced case counter");
        require(requestAllocation.nextRequestChallengeId() == nextOriginCase, "retired intake advanced origin counter");
        require(kernel.CORRECTIONS().caseIdByOrigin(originKey) == 0, "retired intake reserved case");
        require(
            requestAllocation.correctionReviewCaseIdByChallenge(nextOriginCase) == 0, "retired origin reserved case"
        );

        AVARequestAllocation.ResolutionInput memory ordinary = _ordinaryRequestResolution(requestChallenge);
        uint256 nextFinding = kernel.CORRECTIONS().nextFindingId();
        requestVm.prank(VERIFIER_ACTOR);
        CoreCorrectionReviewVm(address(requestVm))
            .expectRevert(
                abi.encodeWithSelector(
                    AVACoreTypes.NotAuthorised.selector,
                    address(requestAllocation),
                    keccak256("ava.extension.request.challenge.resolve.v1")
                )
            );
        requestAllocation.resolveRequestChallenge(ordinary);
        require(kernel.CORRECTIONS().nextFindingId() == nextFinding, "retired origin formed finding");
        require(corrections.findingIdByCase(acceptedCase) == 0, "retired finding retained");
        require(
            requestAllocation.getRequestChallenge(requestChallenge).outcome
                == AVARequestAllocation.ResolutionOutcome.None
        );

        IAVACorrectionReview.ReviewInput memory independent = _requestOriginReviewInput(acceptedCase);
        requestVm.prank(REVIEWER);
        uint256 reviewId = corrections.review(independent);
        uint256 findingId = corrections.findingIdByCase(acceptedCase);
        require(corrections.getCase(acceptedCase).reviewId == reviewId, "retirement blocked accepted review");
        require(corrections.getFinding(findingId).independentReview, "retained review did not form finding");
        require(
            keccak256(abi.encode(corrections.getCase(acceptedCase).input)) == acceptedHistory, "accepted case rewritten"
        );
        require(
            keccak256(abi.encode(requestAllocation.getRequest(requestId))) == requestHistory,
            "request history rewritten"
        );
        bytes32 retainedReview =
            keccak256(abi.encode(corrections.getReview(reviewId), corrections.getFinding(findingId)));

        corrections.setRequestOriginEnabled(APP, address(requestAllocation), true);
        require(!corrections.requestOriginDisabled(APP, address(requestAllocation)), "matching origin not reactivated");
        uint256 newChallenge =
            _fileRetirementChallenge(requestId, kind, SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT, secondEvidence);
        require(newChallenge == nextOriginCase, "failed intake consumed origin identity");
        require(
            requestAllocation.correctionReviewCaseIdByChallenge(newChallenge) == nextCase,
            "failed intake consumed case identity"
        );
        ordinary.challengeId = newChallenge;
        ordinary.expectedPreviousResolutionId = requestChallenge;
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(ordinary);
        uint256 newCase = requestAllocation.correctionReviewCaseIdByChallenge(newChallenge);
        require(
            !corrections.getFinding(corrections.findingIdByCase(newCase)).independentReview, "ordinary finding missing"
        );
        if (kind == AVARequestAllocation.ChallengeTarget.Allocation) {
            executor.execute(requestAllocation, requestId, response, parameters);
        }
        requestVm.expectRevert();
        executor.execute(requestAllocation, requestId, response, parameters);
        require(executor.effects() == 1, "retirement changed effect count");
        require(
            retainedReview == keccak256(abi.encode(corrections.getReview(reviewId), corrections.getFinding(findingId))),
            "review history rewritten"
        );
        require(
            priorHistory
                == keccak256(
                    abi.encode(
                        corrections.getCase(caseId),
                        corrections.getReview(priorReview),
                        corrections.getFinding(priorFinding)
                    )
                ),
            "prior history rewritten"
        );
    }

    function _fileRetirementChallenge(
        uint256 requestId,
        AVARequestAllocation.ChallengeTarget kind,
        address actor,
        bytes32 subject,
        uint256 evidenceId
    ) private returns (uint256) {
        requestVm.prank(actor);
        return requestAllocation.fileRequestChallenge(
            requestId, kind, evidenceId, ROLE_SOURCE, subject, keccak256("retirement concern")
        );
    }

    function _secondRequestFilingEvidence() private returns (uint256) {
        requestVm.prank(SECOND_CHALLENGER);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: SECOND_CHALLENGER_SUBJECT,
                commitment: keccak256("second request challenge evidence"),
                evidenceTypeHash: keccak256("request filing evidence"),
                disclosurePolicyId: requestPolicyId,
                authorityId: SECOND_CHALLENGER_SUBJECT,
                uri: "test:second-request-filing"
            })
        );
    }

    function _ordinaryRequestResolution(uint256 id)
        private
        returns (AVARequestAllocation.ResolutionInput memory input)
    {
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_RESOLVE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_VERIFIER,
                subjectId: _authority(ROLE_VERIFIER),
                commitment: keccak256("ordinary retirement review evidence"),
                evidenceTypeHash: keccak256("ordinary request correction"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_VERIFIER),
                uri: "test:ordinary-request-review"
            })
        );
        input.challengeId = id;
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.decisionEvidenceId = evidence;
        input.outcome = AVARequestAllocation.ResolutionOutcome.Rejected;
        input.reasonHash = keccak256("ordinary request finding");
        input.finding = _findingInput(true);
    }

    function testOriginLifecycleIsAppScopedAndRequiresApplicationAdminAndExistingBinding() public {
        address origin = address(requestAllocation);
        bytes32 otherApp = keccak256("retirement.other.app");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other.namespace"), keccak256("other.authority"), address(this), "test:other-app"
        );
        corrections.bindRequestOrigin(otherApp, origin);
        corrections.setRequestOriginEnabled(APP, origin, false);
        require(!corrections.requestOriginDisabled(otherApp, origin), "retirement leaked across apps");
        corrections.setRequestOriginEnabled(otherApp, origin, false);
        corrections.setRequestOriginEnabled(otherApp, origin, true);
        require(corrections.requestOriginDisabled(APP, origin), "other app reactivated origin");
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        corrections.setRequestOriginEnabled(APP, origin, true);
        require(corrections.requestOriginDisabled(APP, origin), "review permission reactivated origin");
        requestVm.expectRevert();
        corrections.setRequestOriginEnabled(APP, address(0xABCD), false);
        requestVm.expectRevert();
        corrections.setRequestOriginEnabled(APP, address(0xABCD), true);
        require(corrections.requestOriginCodeHash(APP, address(0xABCD)) == bytes32(0), "toggle installed origin");
    }

    function testRequestOriginDisablementDoesNotGateSourceCaseIntake() public {
        corrections.bindRequestOrigin(APP, address(challenges));
        corrections.setRequestOriginEnabled(APP, address(challenges), false);
        (uint256 nextChallenge,,) = _file(
            targetId, keccak256("source after request-origin disable"), SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT
        );
        _screen(nextChallenge);
        uint256 nextCase = challenges.correctionReviewCaseIdByChallenge(nextChallenge);
        require(
            corrections.getCase(nextCase).input.kind == IAVACorrectionReview.TargetKind.Source, "source intake disabled"
        );
    }

    function testReviewPermissionCannotInstallAnActorRelayAndWrongCoreCannotBeBound() public {
        RevertingCorrectionOrigin origin = new RevertingCorrectionOrigin(kernel);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        corrections.bindRequestOrigin(APP, address(origin));
        require(corrections.requestOriginCodeHash(APP, address(origin)) == bytes32(0));
        RevertingCorrectionOrigin wrongCore = new RevertingCorrectionOrigin(AVAGovernanceKernel(address(0xBAD)));
        requestVm.expectRevert();
        corrections.bindRequestOrigin(APP, address(wrongCore));
        require(corrections.requestOriginCodeHash(APP, address(wrongCore)) == bytes32(0));
    }

    function testResidualRecordsExplicitOutcomeWithoutChangingSourceOrVestingChallenge() public {
        _assertNonReversingReview(IAVACorrectionReview.Outcome.Residual);
        require(challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.ReviewResidual);
    }

    function testApplicationAdminHasNoImplicitCorrectionReviewPermission() public {
        IAVACorrectionReview.ReviewInput memory input = _reviewInput(caseId, IAVACorrectionReview.Outcome.Residual, 0);
        input.roleKey = ROLE_PACKAGE;
        input.authorityId = _authority(ROLE_PACKAGE);
        requestVm.expectRevert();
        corrections.review(input);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        evidence.roleKey = ROLE_PACKAGE;
        evidence.subjectId = _authority(ROLE_PACKAGE);
        evidence.authorityId = evidence.subjectId;
        requestVm.expectRevert();
        evidenceRegistry.registerReviewEvidence(evidence, corrections, caseId);
        require(corrections.getCase(caseId).reviewId == 0, "admin reviewed");
    }

    function testRevokedCurrentReviewPermissionRejectsAlreadyRegisteredSupport() public {
        uint256 support = _reviewEvidence(caseId);
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REVIEW_CORRECTION, false);
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, support));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        evidenceRegistry.registerReviewEvidence(evidence, corrections, caseId);
        require(corrections.getCase(caseId).reviewId == 0, "revoked reviewer accepted");
    }

    function testReviewEvidenceRequiresCurrentCanonicalSubjectAcrossRotation() public {
        uint256 oldSupport = _reviewEvidence(caseId);
        bytes32 oldEvidenceHash = keccak256(abi.encode(evidenceRegistry.getEvidence(oldSupport)));
        bytes32 filingHash = keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId)));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _reviewEvidenceInput(caseId);

        input.appId = keccak256("other.app");
        requestVm.prank(REVIEWER);
        CoreCorrectionReviewVm(address(requestVm))
            .expectRevert(
                abi.encodeWithSelector(
                    AVACoreTypes.NotAuthorised.selector, REVIEWER, AVACoreTypes.ACTION_REVIEW_CORRECTION
                )
            );
        evidenceRegistry.registerReviewEvidence(input, corrections, caseId);
        input.appId = APP;
        input.subjectId = CHALLENGER_SUBJECT;
        requestVm.prank(REVIEWER);
        CoreCorrectionReviewVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, caseId));
        evidenceRegistry.registerReviewEvidence(input, corrections, caseId);
        input.subjectId = REVIEW_SUBJECT;

        identityRegistry.deactivateSubject(REVIEW_SUBJECT);
        requestVm.prank(REVIEWER);
        CoreCorrectionReviewVm(address(requestVm))
            .expectRevert(
                abi.encodeWithSelector(
                    AVACoreTypes.NotAuthorised.selector, REVIEWER, AVACoreTypes.ACTION_REVIEW_CORRECTION
                )
            );
        evidenceRegistry.registerReviewEvidence(input, corrections, caseId);

        bytes32 replacement = keccak256("core.correction.review.replacement");
        identityRegistry.assignSubject(REVIEWER, APP, ROLE_REVIEW, replacement, "test:replacement-reviewer");
        requestVm.prank(REVIEWER);
        CoreCorrectionReviewVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.SubjectMismatch.selector, replacement, REVIEW_SUBJECT));
        evidenceRegistry.registerReviewEvidence(input, corrections, caseId);

        input.subjectId = replacement;
        input.authorityId = replacement;
        requestVm.prank(REVIEWER);
        uint256 support = evidenceRegistry.registerReviewEvidence(input, corrections, caseId);
        IAVACorrectionReview.ReviewInput memory review =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.Residual, support);
        review.authorityId = replacement;
        requestVm.prank(REVIEWER);
        uint256 reviewId = corrections.review(review);
        require(corrections.getCase(caseId).reviewId == reviewId, "rotated review not completed");
        require(evidenceRegistry.getEvidence(support).subjectId == replacement, "replacement not recorded");
        require(keccak256(abi.encode(evidenceRegistry.getEvidence(oldSupport))) == oldEvidenceHash, "history changed");
        require(
            keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId))) == filingHash, "filing changed"
        );
    }

    function testOriginalMakerChallengerAndAffectedOwnerCannotReviewOrAdmitSupport() public {
        _assertConflictedActor(VERIFIER_ACTOR, keccak256("maker.review.alias"));
        _assertConflictedActor(CHALLENGER, keccak256("challenger.review.alias"));
        _assertConflictedActor(SOURCE_ACTOR, keccak256("owner.review.alias"));
        require(corrections.getCase(caseId).reviewId == 0, "conflicted review accepted");
    }

    function testOrdinaryFilingEvidenceAndAnotherCasesReviewEvidenceCannotSupportMerits() public {
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, filingEvidenceId));
        uint256 secondTarget = _createStateForCommitment(keccak256("other.source"));
        (uint256 secondChallenge,,) =
            _file(secondTarget, keccak256("other.challenge"), SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT);
        _screen(secondChallenge);
        uint256 otherCase = challenges.correctionReviewCaseIdByChallenge(secondChallenge);
        uint256 otherSupport = _reviewEvidence(otherCase);
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, otherSupport));
        require(corrections.getCase(caseId).reviewId == 0 && corrections.getCase(otherCase).reviewId == 0);
    }

    function testMeritsRequireFreshCaseEvidenceAndNonemptyReason() public {
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Affirmed, 0));
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, 0));
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Residual, 0));
        uint256 support = _reviewEvidence(caseId);
        IAVACorrectionReview.ReviewInput memory input =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, support);
        input.reasonHash = bytes32(0);
        _expectReviewRevert(input);
        require(corrections.getCase(caseId).reviewId == 0, "unsupported merits accepted");
    }

    function testNeutralOutcomesRequireActualEvidenceLossOrTargetChange() public {
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.EvidenceUnavailable, 0));
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.TargetChanged, 0));
        require(corrections.getCase(caseId).reviewId == 0, "neutral label invented loss");
    }

    function testEvidenceUnavailableClosesAcceptedCaseWithoutEvidenceOrSourceChange() public {
        AVAChallengeExtension.ChallengeRecord memory beforeChallenge = challenges.getChallenge(challengeId);
        uint256 beforeHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 support = _reviewEvidence(caseId);
        _expireEvidence(filingEvidenceId, CHALLENGER, CHALLENGER_SUBJECT);
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.EvidenceUnavailable, support));
        _review(caseId, IAVACorrectionReview.Outcome.EvidenceUnavailable, 0);
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == beforeHead, "neutral changed source");
        require(challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.Unavailable);
        _assertClosedWithoutChallengeVesting(beforeChallenge, 0);
    }

    function testRetiredChallengerClosesNeutrallyAndAnotherCanChallenge() public {
        AVAChallengeExtension.ChallengeRecord memory beforeChallenge = challenges.getChallenge(challengeId);
        uint256 beforeHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        bytes32 evidenceHistory = keccak256(abi.encode(evidenceRegistry.getEvidence(filingEvidenceId)));
        bytes32 filingHistory = keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId)));
        require(evidenceRegistry.getEvidence(filingEvidenceId).status == AVACoreTypes.EvidenceStatus.Active);

        identityRegistry.deactivateSubject(CHALLENGER_SUBJECT);
        _review(caseId, IAVACorrectionReview.Outcome.EvidenceUnavailable, 0);
        require(corrections.findingIdByCase(caseId) == 0, "neutral produced finding");
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == beforeHead, "neutral changed source");
        require(challenges.getChallenge(challengeId).outcome == AVAChallengeExtension.ChallengeOutcome.Unavailable);
        _assertClosedWithoutChallengeVesting(beforeChallenge, 0);
        require(keccak256(abi.encode(evidenceRegistry.getEvidence(filingEvidenceId))) == evidenceHistory);
        require(keccak256(abi.encode(challenges.getChallengeTransition(filingHistoryId))) == filingHistory);

        (uint256 nextChallenge,,) =
            _file(targetId, keccak256("after.retired.challenger"), SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT);
        _screen(nextChallenge);
        require(challenges.correctionReviewCaseIdByChallenge(nextChallenge) != 0, "next challenge not accepted");
    }

    function testExpiredReviewSupportCannotResolveMerits() public {
        uint256 support = _reviewEvidence(caseId);
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE, true);
        requestVm.prank(REVIEWER);
        evidenceRegistry.recordEvidenceLifecycle(
            support,
            ROLE_REVIEW,
            REVIEW_SUBJECT,
            AVACoreTypes.EvidenceLifecycleKind.Expire,
            0,
            keccak256("expire.review.support"),
            "test:expire-review"
        );
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, support));
        require(corrections.getCase(caseId).reviewId == 0, "expired support used");
    }

    function testStaleHeadCannotWithdrawAndChangedTargetCanBeNeutrallyClosed() public {
        uint256 originalHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 support = _reviewEvidence(caseId);
        (uint256 secondChallenge,,) =
            _file(targetId, keccak256("second.challenge.same.target"), SECOND_CHALLENGER, SECOND_CHALLENGER_SUBJECT);
        _screen(secondChallenge);
        uint256 secondCase = challenges.correctionReviewCaseIdByChallenge(secondChallenge);
        _review(secondCase, IAVACorrectionReview.Outcome.Withdrawn, _reviewEvidence(secondCase));
        uint256 changedHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        require(changedHead != originalHead, "control did not advance target");
        IAVACorrectionReview.ReviewInput memory stale =
            _reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, support);
        stale.expectedTargetVersion = originalHead;
        _expectReviewRevert(stale);
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Withdrawn, support));
        uint256 reviewId = _review(caseId, IAVACorrectionReview.Outcome.TargetChanged, 0);
        require(corrections.getReview(reviewId).input.evidenceId == 0, "neutral used support");
        require(
            kernel.getRecognisedStateReference(targetId).lastTransitionId == changedHead, "neutral rolled back target"
        );
        require(challenges.getChallenge(challengeId).status == AVAChallengeExtension.ChallengeStatus.Closed);
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "case count not released");
    }

    function testReviewAndEvidenceAdmissionCannotReplayAfterClosure() public {
        uint256 support = _reviewEvidence(caseId);
        uint256 reviewId = _review(caseId, IAVACorrectionReview.Outcome.Withdrawn, support);
        uint256 head = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        _expectReviewRevert(_reviewInput(caseId, IAVACorrectionReview.Outcome.Residual, support));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        evidenceRegistry.registerReviewEvidence(evidence, corrections, caseId);
        require(corrections.getCase(caseId).reviewId == reviewId, "review replayed");
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == head, "replay changed head");
    }

    function testUnscreenedChallengeCannotCreateAReviewCaseOrReceiveReviewEvidence() public {
        uint256 secondTarget = _createStateForCommitment(keccak256("unscreened.source"));
        (uint256 unscreened,,) = _file(secondTarget, keccak256("unscreened.challenge"), CHALLENGER, CHALLENGER_SUBJECT);
        require(challenges.correctionReviewCaseIdByChallenge(unscreened) == 0, "unaccepted case registered");
        IAVACorrectionReview.CaseInput memory forged = corrections.getCase(caseId).input;
        forged.originCaseId = unscreened;
        forged.targetId = secondTarget;
        forged.sourceStateId = secondTarget;
        requestVm.expectRevert();
        corrections.registerCase(forged);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        evidenceRegistry.registerReviewEvidence(evidence, corrections, 0);
    }

    function testReviewAdmissionSurvivesOrdinaryEvidencePolicyVeto() public {
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert(CoreReviewOrdinaryVetoPolicy.OrdinaryEvidenceVeto.selector);
        evidenceRegistry.registerEvidence(evidence);
        uint256 support = _reviewEvidence(caseId);
        require(
            evidenceRegistry.reviewEvidenceRegistryById(support) == address(corrections), "registry purpose missing"
        );
        require(evidenceRegistry.reviewEvidenceCaseIdById(support) == caseId, "case purpose missing");
        _review(caseId, IAVACorrectionReview.Outcome.Residual, support);
    }

    function testReviewReceiptCannotFormOrdinaryStateButOrdinaryReceiptCan() public {
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REGISTER_GOVERNED_OBJECT, true);
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        uint256 support = _reviewEvidence(caseId);
        AVAGovernanceKernel.GovernedObjectInput memory object = _reviewerObject(support);
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        kernel.registerGovernedObject(object);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory ordinary = _reviewEvidenceInput(caseId);
        ordinary.evidenceTypeHash = keccak256("ordinary.support");
        requestVm.prank(REVIEWER);
        uint256 ordinaryEvidence = evidenceRegistry.registerEvidence(ordinary);
        requestVm.startPrank(REVIEWER);
        uint256 objectId = kernel.registerGovernedObject(_reviewerObject(ordinaryEvidence));
        uint256 stateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_REVIEW,
                authorityId: REVIEW_SUBJECT,
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Registered,
                reasonHash: keccak256("ordinary.formation"),
                reasonURI: "test:ordinary-formation"
            })
        );
        requestVm.stopPrank();
        require(kernel.getRecognisedStateReference(stateId).evidenceReceiptId == ordinaryEvidence, "control failed");
    }

    function testReviewReceiptCannotSupportOrdinaryCorrectionButOrdinaryReceiptCan() public {
        requestPackageId = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 3);
        _bindChallengePackage();
        uint256 freshTarget = _createStateForCommitment(keccak256("permissive.source"));
        (uint256 freshChallenge,,) =
            _file(freshTarget, keccak256("permissive.challenge"), CHALLENGER, CHALLENGER_SUBJECT);
        _screen(freshChallenge);
        uint256 freshCase = challenges.correctionReviewCaseIdByChallenge(freshChallenge);
        uint256 support = _reviewEvidence(freshCase);
        AVAChallengeExtension.ChallengeResolutionInput memory ordinary =
            _ordinaryResolution(freshChallenge, AVAChallengeExtension.ChallengeOutcome.Upheld);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        challenges.resolveChallengeWithEvidence(ordinary, support);
        authorityMatrix.setPermission(APP, ROLE_REVIEW, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _reviewEvidenceInput(freshCase);
        input.evidenceTypeHash = keccak256("ordinary.support");
        requestVm.prank(REVIEWER);
        uint256 ordinaryEvidence = evidenceRegistry.registerEvidence(input);
        requestVm.prank(VERIFIER_ACTOR);
        challenges.resolveChallengeWithEvidence(ordinary, ordinaryEvidence);
        require(kernel.getRecognisedStateReference(freshTarget).status == AVACoreTypes.RecognisedStateStatus.Voided);
        _expectReviewRevert(_reviewInput(freshCase, IAVACorrectionReview.Outcome.Residual, support));
        require(corrections.getCase(freshCase).reviewId == 0, "ordinary/Core race resolved twice");
    }

    function _installVetoPackage() private {
        vetoPolicy = new CoreReviewOrdinaryVetoPolicy();
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(new M14PermissiveApplicationModule(APP));
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            new AVACoreRulePackageRegistry.ModuleBinding[](base.length + 1);
        for (uint256 i; i < base.length; ++i) {
            bindings[i] = base[i];
        }
        bindings[4] = _coreBinding(AVACapabilityKeys.EVIDENCE_POLICY, address(vetoPolicy));
        bindings[6] = _coreBinding(AVACapabilityKeys.CHALLENGE_POLICY, address(vetoPolicy));
        bindings[7] = _coreBinding(AVACapabilityKeys.AUTHORITY_POLICY, address(vetoPolicy));
        bindings[base.length] = _coreBinding(AVACapabilityKeys.ANTI_ABUSE, address(vetoPolicy));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:ordinary-veto"
            ),
            requestPackageId,
            bindings
        );
        _bindChallengePackage();
    }

    function _bindChallengePackage() private {
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
    }

    function _file(uint256 target, bytes32 seed, address actor, bytes32 subject)
        private
        returns (uint256 id, uint256 evidenceId, uint256 stateId)
    {
        requestVm.startPrank(actor);
        evidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: subject,
                commitment: seed,
                evidenceTypeHash: keccak256("challenge.support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: subject,
                uri: "test:filing-evidence"
            })
        );
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: keccak256("core.review.concern"),
                objectCommitment: seed,
                parentObjectId: kernel.getRecognisedStateReference(target).governedObjectId,
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
                challengedRecognisedStateId: target,
                roleKey: ROLE_SOURCE,
                reasonHash: seed,
                reasonURI: "test:challenge"
            })
        );
        requestVm.stopPrank();
    }

    function _screen(uint256 id) private {
        requestVm.prank(VERIFIER_ACTOR);
        challenges.screenChallenge(id, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
    }

    function _reviewEvidenceInput(uint256 id)
        private
        view
        returns (AVAEvidenceRegistry.EvidenceRegistrationInput memory)
    {
        IAVACorrectionReview.CaseInput memory item = corrections.getCase(id).input;
        return AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: item.appId,
            workflowKey: item.workflowKey,
            packageId: item.packageId,
            roleKey: ROLE_REVIEW,
            subjectId: REVIEW_SUBJECT,
            commitment: keccak256(abi.encode("fresh.review", id)),
            evidenceTypeHash: REVIEW_SUPPORT,
            disclosurePolicyId: requestPolicyId,
            authorityId: REVIEW_SUBJECT,
            uri: "test:review-evidence"
        });
    }

    function _reviewEvidence(uint256 id) private returns (uint256) {
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _reviewEvidenceInput(id);
        requestVm.prank(REVIEWER);
        return evidenceRegistry.registerReviewEvidence(input, corrections, id);
    }

    function _reviewInput(uint256 id, IAVACorrectionReview.Outcome outcome, uint256 support)
        private
        view
        returns (IAVACorrectionReview.ReviewInput memory)
    {
        uint256 target = corrections.getCase(id).input.targetId;
        return IAVACorrectionReview.ReviewInput({
            caseId: id,
            expectedTargetVersion: kernel.getRecognisedStateReference(target).lastTransitionId,
            outcome: outcome,
            evidenceId: support,
            roleKey: ROLE_REVIEW,
            authorityId: REVIEW_SUBJECT,
            reasonHash: keccak256(abi.encode("review.reason", id, outcome)),
            asset: address(0),
            recipient: address(0),
            amount: 0,
            finding: _findingInput(
                outcome != IAVACorrectionReview.Outcome.EvidenceUnavailable
                    && outcome != IAVACorrectionReview.Outcome.TargetChanged
            )
        });
    }

    function _review(uint256 id, IAVACorrectionReview.Outcome outcome, uint256 support) private returns (uint256) {
        IAVACorrectionReview.ReviewInput memory input = _reviewInput(id, outcome, support);
        requestVm.prank(REVIEWER);
        return corrections.review(input);
    }

    function _expectReviewRevert(IAVACorrectionReview.ReviewInput memory input) private {
        requestVm.prank(REVIEWER);
        requestVm.expectRevert();
        corrections.review(input);
    }

    function _ordinaryResolution(uint256 id, AVAChallengeExtension.ChallengeOutcome outcome)
        private
        view
        returns (AVAChallengeExtension.ChallengeResolutionInput memory)
    {
        uint256 target = challenges.getChallenge(id).challengedRecognisedStateId;
        return AVAChallengeExtension.ChallengeResolutionInput({
            challengeId: id,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            outcome: outcome,
            correctionStatus: outcome == AVAChallengeExtension.ChallengeOutcome.Upheld
                ? AVACoreTypes.RecognisedStateStatus.Voided
                : kernel.getRecognisedStateReference(target).status,
            reasonHash: keccak256(abi.encode("ordinary.reason", id, outcome)),
            reasonURI: "test:ordinary-resolution",
            finding: _findingInput(
                outcome != AVAChallengeExtension.ChallengeOutcome.Unavailable
                    && outcome != AVAChallengeExtension.ChallengeOutcome.TargetChangedNoReversal
            )
        });
    }

    function _expireEvidence(uint256 id, address actor, bytes32 subject) private {
        requestVm.prank(actor);
        evidenceRegistry.recordEvidenceLifecycle(
            id, ROLE_SOURCE, subject, AVACoreTypes.EvidenceLifecycleKind.Expire, 0, keccak256("expire"), "test:expire"
        );
    }

    function _assertNonReversingReview(IAVACorrectionReview.Outcome outcome) private {
        AVAChallengeExtension.ChallengeRecord memory beforeChallenge = challenges.getChallenge(challengeId);
        uint256 targetHead = kernel.getRecognisedStateReference(targetId).lastTransitionId;
        uint256 support = _reviewEvidence(caseId);
        uint256 reviewId = _review(caseId, outcome, support);
        require(kernel.getRecognisedStateReference(targetId).lastTransitionId == targetHead, "review changed source");
        require(corrections.getReview(reviewId).input.outcome == outcome, "outcome missing");
        _assertClosedWithoutChallengeVesting(beforeChallenge, support);
    }

    function _assertClosedWithoutChallengeVesting(
        AVAChallengeExtension.ChallengeRecord memory beforeChallenge,
        uint256 support
    ) private view {
        AVAChallengeExtension.ChallengeRecord memory afterChallenge = challenges.getChallenge(challengeId);
        require(afterChallenge.status == AVAChallengeExtension.ChallengeStatus.Closed, "case not closed");
        require(challenges.openChallengeCountByRecognisedState(targetId) == 0, "open count retained");
        require(afterChallenge.evidenceReceiptId == filingEvidenceId, "original filing replaced");
        require(afterChallenge.decisionEvidenceReceiptId == support, "decision support not recorded");
        require(
            kernel.getRecognisedStateReference(challengeStateId).lastTransitionId
                == beforeChallenge.challengeStateTransitionIdAtFiling,
            "challenge vested"
        );
        require(
            kernel.getRecognisedStateReference(challengeStateId).status
                == AVACoreTypes.RecognisedStateStatus.Challengeable,
            "review produced challenge reward state"
        );
    }

    function _assertConflictedActor(address actor, bytes32 subject) private {
        identityRegistry.assignSubject(actor, APP, ROLE_REVIEW, subject, "test:conflicted-review-alias");
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = _reviewEvidenceInput(caseId);
        evidence.subjectId = subject;
        evidence.authorityId = subject;
        requestVm.prank(actor);
        requestVm.expectRevert();
        evidenceRegistry.registerReviewEvidence(evidence, corrections, caseId);
        IAVACorrectionReview.ReviewInput memory input = _reviewInput(caseId, IAVACorrectionReview.Outcome.Residual, 0);
        input.authorityId = subject;
        requestVm.prank(actor);
        requestVm.expectRevert();
        corrections.review(input);
    }

    function _reviewerObject(uint256 evidenceId) private view returns (AVAGovernanceKernel.GovernedObjectInput memory) {
        return AVAGovernanceKernel.GovernedObjectInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            roleKey: ROLE_REVIEW,
            objectTypeKey: keccak256("ordinary.object"),
            objectCommitment: keccak256("ordinary.commitment"),
            parentObjectId: 0,
            subjectId: REVIEW_SUBJECT,
            evidenceReceiptId: evidenceId,
            disclosurePolicyId: requestPolicyId,
            metadataHash: keccak256("ordinary.metadata"),
            authorityId: REVIEW_SUBJECT,
            uri: "test:ordinary-object"
        });
    }
}
