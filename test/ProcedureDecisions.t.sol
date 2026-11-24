// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DecisionSetFixture, DecisionExecutor} from "./DecisionSet.t.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {IAVAProcedurePolicy} from "../src/core/interfaces/IAVAProcedurePolicy.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAProcedureAdjudication} from "../src/extensions/decisions/AVAProcedureAdjudication.sol";
import {AVABasicProcedurePolicy} from "../src/extensions/decisions/AVABasicProcedurePolicy.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";

contract RejectEveryProcedureResolution is IAVAProcedurePolicy, RuleModuleIdentity {
    function validateProcedureReview(Review calldata) external pure {
        revert("all ordinary reviews vetoed");
    }
}

contract ProcedureReviewingExecutor is DecisionExecutor {
    function submitReviewEvidence(
        AVAEvidenceRegistry evidence,
        AVAEvidenceRegistry.EvidenceRegistrationInput calldata input,
        IAVACorrectionReview registry,
        uint256 caseId
    ) external returns (uint256) {
        return evidence.registerReviewEvidence(input, registry, caseId);
    }

    function submitReview(IAVACorrectionReview registry, IAVACorrectionReview.ReviewInput calldata input)
        external
        returns (uint256)
    {
        return registry.review(input);
    }
}

interface ProcedureExactRevertVm {
    function expectRevert(bytes calldata revertData) external;
}

/// @notice All authority, receipt, package, support and execution checks use the real Core.
contract ProcedureDecisionsTest is DecisionSetFixture {
    AVAProcedureAdjudication internal adjudicator;
    AVABasicProcedurePolicy internal reviewPolicy;

    function setUp() public override {
        super.setUp();
        reviewPolicy = new AVABasicProcedurePolicy(APP, REQUEST_WORKFLOW, true);
        adjudicator = new AVAProcedureAdjudication(registry, reviewPolicy);
        policy = new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _procedureOptions());
        _installProcedurePackage();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, registry.ACTION_FILE_PROCEDURE_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, registry.ACTION_RESOLVE_PROCEDURE_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
    }

    function testUnsupportedDContainsOnlyExplicitlyAuthorisedProcedureAndCreatesNoRecognition() public {
        uint256 id = _emptyRequest("unsupported");
        uint256 states = kernel.nextRecognisedStateId();
        uint256 objects = kernel.nextGovernedObjectId();
        uint256 transitions = kernel.nextTransitionId();
        require(_d(id).length == 0, "invented procedural authority");
        _permit(ROLE_ALLOCATOR, IAVADecisionPolicy.Kind.SeekEvidence, true);
        IAVADecisionPolicy.Option[] memory choices = _d(id);
        require(choices.length == 1 && choices[0].key == _key(IAVADecisionPolicy.Kind.SeekEvidence), "wrong D");
        uint256 decision = _choose(id, choices[0].key, 0, 0);
        require(registry.getDecision(decision).witness.length == 0, "manufactured witness");
        require(registry.getDecision(decision).executionRequestId == 0, "manufactured execution");
        require(kernel.nextRecognisedStateId() == states, "recognition created");
        require(kernel.nextGovernedObjectId() == objects && kernel.nextTransitionId() == transitions, "Core changed");
    }

    function testDecisionRegistryRuntimeLeavesAtLeast512BytesOfHeadroom() public view {
        require(address(registry).code.length <= 24_576 - 512, "decision runtime lacks 512 bytes headroom");
    }

    function testAllSixProcedureKindsHaveLocalControlsWithoutPrivilegesOrDisclosure() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 policies = disclosureRegistry.nextPolicyId();
        uint256 evidence = evidenceRegistry.nextEvidenceId();
        uint256 states = kernel.nextRecognisedStateId();
        for (uint256 i = 1; i <= 6; ++i) {
            IAVADecisionPolicy.Kind kind = IAVADecisionPolicy.Kind(i);
            uint256 id = _emptyRequest(keccak256(abi.encode("kind", i)));
            uint256 previous;
            if (kind == IAVADecisionPolicy.Kind.Resume) previous = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
            uint256 decision = _procedure(id, kind, previous);
            AVADecisionRegistry.AtomicRequest memory item = registry.getRequest(id);
            require(item.closed == (kind == IAVADecisionPolicy.Kind.Close), "wrong close state");
            require(
                item.paused == (kind != IAVADecisionPolicy.Kind.Resume && kind != IAVADecisionPolicy.Kind.Close),
                "wrong pause state"
            );
            require(item.lastDecisionId == decision && item.allocationDecisionId == 0, "wrong decision head");
            require(registry.getDecision(decision).witness.length == 0, "procedure gained support");
            if (kind == IAVADecisionPolicy.Kind.Close) require(_d(id).length == 0, "closed request admits decisions");
        }
        require(
            !authorityMatrix.isAuthorised(
                ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_VEST_RECOGNISED_STATE
            ),
            "granted recognition power"
        );
        require(
            !authorityMatrix.isAuthorised(
                ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_REGISTER_DISCLOSURE_POLICY
            ),
            "granted disclosure power"
        );
        require(
            disclosureRegistry.nextPolicyId() == policies && evidenceRegistry.nextEvidenceId() == evidence,
            "disclosure or evidence created"
        );
        require(kernel.nextRecognisedStateId() == states, "procedure created recognition");
    }

    function testProcedureActionsAreIsolatedAndRevocationImmediatelyRemovesChoice() public {
        uint256 id = _emptyRequest("permissions");
        _permit(ROLE_ALLOCATOR, IAVADecisionPolicy.Kind.Pause, true);
        require(_d(id).length == 1, "pause authority leaked");
        requestVm.expectRevert();
        _procedure(id, IAVADecisionPolicy.Kind.Close, 0);
        _permit(ROLE_ALLOCATOR, IAVADecisionPolicy.Kind.Pause, false);
        require(_d(id).length == 0, "revoked pause remains");
        requestVm.expectRevert();
        _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 evidence = _evidence(SOURCE_ACTOR, ROLE_SOURCE, _authority(ROLE_SOURCE), requestPackageId);
        _permit(ROLE_ALLOCATOR, IAVADecisionPolicy.Kind.Pause, true);
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, registry.ACTION_FILE_PROCEDURE_CHALLENGE(), false);
        requestVm.expectRevert();
        _file(target, evidence);
        require(adjudicator.nextChallengeId() == 1, "revoked filer recorded");
    }

    function testResumeCannotManufactureSupportOrAnApproval() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("resume unsupported");
        requestVm.expectRevert();
        _procedure(id, IAVADecisionPolicy.Kind.Resume, 0);
        uint256 pause = _procedure(id, IAVADecisionPolicy.Kind.Withhold, 0);
        uint256 resumed = _procedure(id, IAVADecisionPolicy.Kind.Resume, pause);
        require(!registry.getRequest(id).paused && registry.getRequest(id).allocationDecisionId == 0, "resume approved");
        require(registry.getEligibleWitnesses(id).length == 0, "resume supplied evidence");
        require(registry.getDecision(resumed).previousDecisionId == pause, "resume lost lineage");
        IAVADecisionPolicy.Option[] memory choices = _d(id);
        for (uint256 i; i < choices.length; ++i) {
            require(choices[i].kind != IAVADecisionPolicy.Kind.Substantive, "unsupported positive");
        }
        requestVm.expectRevert();
        _choose(id, POSITIVE, 0, resumed);
    }

    function testPauseBlocksActualConsumeAndResumePreservesCanonicalApproval() public {
        _permitAll(ROLE_ALLOCATOR);
        (uint256 id, uint256 execution, uint256 positive) = _approved("pause execution");
        bytes32 approval = keccak256(abi.encode(requestAllocation.getRequest(execution)));
        uint256 pause = _procedure(id, IAVADecisionPolicy.Kind.Pause, positive);
        requestVm.expectRevert();
        executor.execute(requestAllocation, execution, RESPONSE, PARAMETERS);
        uint256 resumed = _procedure(id, IAVADecisionPolicy.Kind.Resume, pause);
        require(registry.getRequest(id).allocationDecisionId == positive, "resume replaced approval");
        require(registry.getDecision(resumed).executionRequestId == 0, "resume fabricated approval");
        require(keccak256(abi.encode(requestAllocation.getRequest(execution))) == approval, "approval record changed");
        executor.execute(requestAllocation, execution, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(execution).consumed, "resume failed to release control");
    }

    function testChooseAndPendingReviewUseExactCurrentHeadCAS() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("CAS");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        requestVm.expectRevert();
        _procedure(id, IAVADecisionPolicy.Kind.SeekEvidence, 0);
        uint256 head = _procedure(id, IAVADecisionPolicy.Kind.Escalate, target);
        uint256 evidence = _resolverEvidence();
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Affirmed, evidence);
        _expectResolutionRevert(input);
        input.expectedCurrentDecisionId = head;
        uint256 resolution = _resolve(input);
        require(adjudicator.getResolution(resolution).currentDecisionId == head, "lost observed head");
        require(registry.getRequest(id).lastDecisionId == head && registry.getRequest(id).paused, "review rewound head");
    }

    function testSubstantiveDecisionCannotBeFiledForProcedureReview() public {
        (,, uint256 positive) = _approved("substantive target");
        uint256 evidence = _sourceEvidence();
        requestVm.expectRevert();
        _file(positive, evidence);
        require(adjudicator.nextChallengeId() == 1, "substantive filing accepted");
    }

    function testFilingRequiresCanonicalActorActiveEvidenceAndExactPackage() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("filing gates");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 ownEvidence = _sourceEvidence();
        uint256 otherEvidence = _resolverEvidence();
        requestVm.expectRevert();
        _file(target, otherEvidence);
        bytes32 source = _authority(ROLE_SOURCE);
        requestVm.prank(address(0xBAD));
        requestVm.expectRevert();
        adjudicator.file(target, ownEvidence, ROLE_SOURCE, source, REASON);
        _revokeEvidence(ownEvidence);
        requestVm.expectRevert();
        _file(target, ownEvidence);
        _installProcedurePackage();
        uint256 currentEvidence = _sourceEvidence();
        requestVm.expectRevert();
        _file(target, currentEvidence);
        require(adjudicator.nextChallengeId() == 1, "invalid filing appended");
    }

    function testReviewIndependenceUsesActualAccountsIncludingExtraRoles() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("account independence");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        bytes32 role = keccak256("extra resolver role");
        authorityMatrix.setPermission(APP, role, registry.ACTION_RESOLVE_PROCEDURE_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, role, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        address[2] memory forbidden = [SOURCE_ACTOR, ALLOCATOR_ACTOR];
        for (uint256 i; i < forbidden.length; ++i) {
            bytes32 subject = keccak256(abi.encode("extra subject", i));
            identityRegistry.assignSubject(forbidden[i], APP, role, subject, "test:extra role");
            uint256 evidence = _evidence(forbidden[i], role, subject, requestPackageId);
            AVAProcedureAdjudication.ResolutionInput memory input =
                _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, evidence);
            input.roleKey = role;
            input.authorityId = subject;
            requestVm.prank(forbidden[i]);
            requestVm.expectRevert();
            adjudicator.resolve(input);
        }
        _resolve(_resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence()));
        require(!registry.getRequest(id).paused, "independent resolver denied");
    }

    function testWithdrawnReversesOnlyCurrentControlAndKeepsPositiveApprovalAndRecords() public {
        _permitAll(ROLE_ALLOCATOR);
        (uint256 id, uint256 execution, uint256 positive) = _approved("withdraw pause");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, positive);
        bytes32 targetHash = keccak256(abi.encode(registry.getDecision(target)));
        uint256 challenge = _file(target, _sourceEvidence());
        uint256 resolution =
            _resolve(_resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence()));
        AVADecisionRegistry.AtomicRequest memory item = registry.getRequest(id);
        require(!item.paused && !item.closed && item.lastDecisionId == target, "withdraw rewrote history");
        require(
            item.allocationDecisionId == positive && registry.procedureDisposition(target) == resolution,
            "withdraw lost approval or disposition"
        );
        require(keccak256(abi.encode(registry.getDecision(target))) == targetHash, "target record changed");
        require(adjudicator.getResolution(resolution).replacementDecisionId == 0, "withdraw appended replacement");
        executor.execute(requestAllocation, execution, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(execution).consumed, "existing positive effect lost");
    }

    function testReplacementNeedsItsOwnAuthorityAndAppendsReviewLineage() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("replace");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Replaced, _resolverEvidence());
        input.replacementKey = _key(IAVADecisionPolicy.Kind.Close);
        _expectResolutionRevert(input);
        require(
            adjudicator.getChallenge(challenge).resolutionId == 0 && registry.procedureDisposition(target) == 0,
            "failed replacement left writes"
        );
        _permit(ROLE_VERIFIER, IAVADecisionPolicy.Kind.Close, true);
        uint256 resolution = _resolve(input);
        uint256 replacement = adjudicator.getResolution(resolution).replacementDecisionId;
        AVADecisionRegistry.DecisionRecord memory record = registry.getDecision(replacement);
        require(record.previousDecisionId == target && record.actor == VERIFIER_ACTOR, "replacement provenance");
        require(
            record.option.kind == IAVADecisionPolicy.Kind.Close && record.witness.length == 0
                && record.executionRequestId == 0,
            "replacement meaning"
        );
        require(
            registry.procedureReviewIdByDecision(replacement) == resolution
                && registry.procedureDisposition(target) == resolution,
            "review lineage absent"
        );
        require(
            registry.getRequest(id).closed && !registry.getRequest(id).paused, "replacement did not restore then apply"
        );
    }

    function testReviewCannotReplaceProcedureWithSubstantiveOption() public {
        _permitAll(ROLE_ALLOCATOR);
        IAVADecisionPolicy.Request memory request = _input("no substantive substitution");
        uint256 id = _open(request, _pool(request, 1));
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Replaced, _resolverEvidence());
        input.replacementKey = POSITIVE;
        _expectResolutionRevert(input);
        require(
            registry.getRequest(id).paused && registry.getRequest(id).allocationDecisionId == 0,
            "substantive substitution took effect"
        );
    }

    function testSubstantiveProcedureReviewRequiresClaimWithoutOrphanFinding() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("bounded procedural conclusion");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence());
        input.finding.claimHash = bytes32(0);
        _expectResolutionRevert(input);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        uint256 caseId = adjudicator.correctionReviewCaseIdByChallenge(challenge);
        require(corrections.findingIdByCase(caseId) == 0, "failed procedure left finding");
        requestVm.expectRevert();
        corrections.getFinding(1);
        require(
            registry.getRequest(id).paused && adjudicator.getChallenge(challenge).resolutionId == 0,
            "failed claim changed procedure"
        );
        input.finding = _findingInput(true);
        _resolve(input);
        require(corrections.findingIdByCase(caseId) == 1 && !registry.getRequest(id).paused, "claim not applied");
    }

    function testLostFilingEvidenceAllowsNeutralZeroEvidenceResolutionWithoutControlChange() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("lost evidence");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Escalate, 0);
        uint256 filingEvidence = _sourceEvidence();
        uint256 challenge = _file(target, filingEvidence);
        _revokeEvidence(filingEvidence);
        bytes32 beforeState = keccak256(abi.encode(registry.getRequest(id)));
        AVAProcedureAdjudication.ResolutionInput memory neutral =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.EvidenceUnavailable, 0);
        neutral.finding = _findingInput(true);
        _expectResolutionRevert(neutral);
        neutral.finding = _findingInput(false);
        uint256 resolution = _resolve(neutral);
        require(
            kernel.CORRECTIONS().findingIdByCase(adjudicator.correctionReviewCaseIdByChallenge(challenge)) == 0,
            "neutral procedure manufactured finding"
        );
        require(adjudicator.getResolution(resolution).decisionEvidenceId == 0, "neutral needs new evidence");
        require(
            keccak256(abi.encode(registry.getRequest(id))) == beforeState && registry.procedureDisposition(target) == 0,
            "neutral changed controls"
        );
    }

    function testActiveFilingCannotClaimEvidenceUnavailableAndResolutionIsAppendOnly() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("active filing");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        _expectResolutionRevert(_resolution(challenge, target, IAVAProcedurePolicy.Outcome.EvidenceUnavailable, 0));
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Affirmed, _resolverEvidence());
        uint256 resolution = _resolve(input);
        bytes32 record = keccak256(abi.encode(adjudicator.getResolution(resolution)));
        input.outcome = IAVAProcedurePolicy.Outcome.Withdrawn;
        _expectResolutionRevert(input);
        require(keccak256(abi.encode(adjudicator.getResolution(resolution))) == record, "resolution mutated");
        require(
            registry.getRequest(id).paused && registry.procedureDisposition(target) == 0, "affirmation changed controls"
        );
    }

    function testChangedOrDisposedTargetResolvesNeutrallyWithoutRewindingLaterDecision() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("changed target");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 evidence = _sourceEvidence();
        uint256 first = _file(target, evidence);
        bytes32 source = _authority(ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        uint256 second = adjudicator.file(target, evidence, ROLE_SOURCE, source, keccak256("second issue"));
        _expectResolutionRevert(_resolution(first, target, IAVAProcedurePolicy.Outcome.TargetChanged, 0));
        _resolve(_resolution(first, target, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence()));
        _resolve(_resolution(second, target, IAVAProcedurePolicy.Outcome.TargetChanged, 0));
        require(
            !registry.getRequest(id).paused && registry.getRequest(id).lastDecisionId == target,
            "disposed target resurrected"
        );
        uint256 later = _procedure(id, IAVADecisionPolicy.Kind.SeekEvidence, target);
        requestVm.prank(SOURCE_ACTOR);
        uint256 third = adjudicator.file(target, evidence, ROLE_SOURCE, source, keccak256("later issue"));
        _expectResolutionRevert(_resolution(third, later, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence()));
        _resolve(_resolution(third, later, IAVAProcedurePolicy.Outcome.TargetChanged, 0));
        require(
            registry.getRequest(id).lastDecisionId == later && registry.getRequest(id).paused, "later control rewound"
        );
    }

    function testAcceptedReviewSurvivesExpiryLostOriginalSupportAndPackageSupersession() public {
        _permitAll(ROLE_ALLOCATOR);
        IAVADecisionPolicy.Request memory input = _input("historical review");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        uint256 oldPackage = requestPackageId;
        uint256 witnessEvidence = kernel.getRecognisedStateReference(pool[0].recognisedStateId).evidenceReceiptId;
        _revokeEvidence(witnessEvidence);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        _installProcedurePackage();
        requestVm.warp(input.validUntil + 1);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory receipt =
            _receipt(ROLE_VERIFIER, _authority(ROLE_VERIFIER), oldPackage);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 evidence = evidenceRegistry.registerCorrectionEvidence(receipt, requestPackageId, REASON);
        uint256 resolution = _resolve(_resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, evidence));
        require(evidenceRegistry.isCorrectionEvidence(evidence), "ordinary evidence substituted");
        require(
            adjudicator.getResolution(resolution).decisionEvidenceId == evidence && !registry.getRequest(id).paused,
            "historical review blocked"
        );
        require(
            registry.getRequest(id).input.packageId == oldPackage && registry.getEligibleWitnesses(id).length == 0,
            "historical binding or loss changed"
        );
    }

    function testRevokedResolverAndNewCanonicalSubjectCannotUseOldAuthorityOrReceipt() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("resolver revocation");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        uint256 evidence = _resolverEvidence();
        AVAProcedureAdjudication.ResolutionInput memory input =
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, evidence);
        bytes32 resolveAction = registry.ACTION_RESOLVE_PROCEDURE_CHALLENGE();
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, resolveAction, false);
        _expectResolutionRevert(input);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, resolveAction, true);
        identityRegistry.deactivateSubject(input.authorityId);
        bytes32 replacement = keccak256("fresh resolver subject");
        identityRegistry.assignSubject(VERIFIER_ACTOR, APP, ROLE_VERIFIER, replacement, "test:fresh resolver");
        _expectResolutionRevert(input);
        input.authorityId = replacement;
        _expectResolutionRevert(input);
        input.decisionEvidenceId = _evidence(VERIFIER_ACTOR, ROLE_VERIFIER, replacement, requestPackageId);
        _resolve(input);
        require(!registry.getRequest(id).paused, "fresh canonical resolver denied");
    }

    function testForgedExternalApplyAndReviewPolicyIdentityDriftFailClosed() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("forged review");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        AVADecisionRegistry.ProcedureApplication memory forged = AVADecisionRegistry.ProcedureApplication(
            target,
            target,
            77,
            IAVAProcedurePolicy.Outcome.Withdrawn,
            bytes32(0),
            VERIFIER_ACTOR,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            REASON
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        registry.applyProcedureReview(forged);
        uint256 evidence = _resolverEvidence();
        AVABasicProcedurePolicy different = new AVABasicProcedurePolicy(APP, keccak256("different workflow"), true);
        requestVm.etch(address(reviewPolicy), address(different).code);
        _expectResolutionRevert(_resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, evidence));
        require(
            registry.getRequest(id).paused && adjudicator.getChallenge(challenge).resolutionId == 0,
            "fail-closed surface mutated"
        );
    }

    function testCoreProcedureReviewRejectsAffectedExecutorAtEvidenceAdmissionAndReview() public {
        ProcedureReviewingExecutor affected = new ProcedureReviewingExecutor();
        executor = affected;
        _permitAll(ROLE_ALLOCATOR);
        (uint256 id,, uint256 positive) = _approved("affected executor conflict");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, positive);
        uint256 challenge = _file(target, _sourceEvidence());
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        uint256 caseId = adjudicator.correctionReviewCaseIdByChallenge(challenge);
        bytes32 role = keccak256("executor review role");
        bytes32 subject = keccak256("executor review subject");
        identityRegistry.assignSubject(address(affected), APP, role, subject, "test:executor-reviewer");
        authorityMatrix.setPermission(APP, role, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        require(
            authorityMatrix.isAuthorised(address(affected), APP, role, AVACoreTypes.ACTION_REVIEW_CORRECTION),
            "conflict fixture lacks review authority"
        );
        AVAEvidenceRegistry.EvidenceRegistrationInput memory receipt = _receipt(role, subject, requestPackageId);
        bytes memory conflictError = abi.encodeWithSelector(
            AVACoreTypes.NotAuthorised.selector, address(affected), AVACoreTypes.ACTION_REVIEW_CORRECTION
        );
        ProcedureExactRevertVm(address(requestVm)).expectRevert(conflictError);
        affected.submitReviewEvidence(evidenceRegistry, receipt, corrections, caseId);
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = caseId;
        input.expectedTargetVersion = target;
        input.outcome = IAVACorrectionReview.Outcome.Withdrawn;
        input.finding = _findingInput(true);
        input.roleKey = role;
        input.authorityId = subject;
        input.reasonHash = REASON;
        ProcedureExactRevertVm(address(requestVm)).expectRevert(conflictError);
        affected.submitReview(corrections, input);
        require(
            registry.getRequest(id).paused && registry.getRequest(id).allocationDecisionId == positive,
            "conflicted review changed pending control"
        );
    }

    function testCoreReviewWithdrawsVetoedPauseAndRetainsPositiveExecution() public {
        adjudicator = new AVAProcedureAdjudication(registry, new RejectEveryProcedureResolution());
        _installProcedurePackage();
        _permitAll(ROLE_ALLOCATOR);
        (uint256 id, uint256 execution, uint256 positive) = _approved("Core review preserves approval");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, positive);
        bytes32 oldDecision = keccak256(abi.encode(registry.getDecision(target)));
        uint256 challenge = _file(target, _sourceEvidence());
        _expectResolutionRevert(
            _resolution(challenge, target, IAVAProcedurePolicy.Outcome.Withdrawn, _resolverEvidence())
        );
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        uint256 caseId = adjudicator.correctionReviewCaseIdByChallenge(challenge);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory receipt =
            _receipt(ROLE_VERIFIER, _authority(ROLE_VERIFIER), requestPackageId);
        requestVm.prank(VERIFIER_ACTOR);
        uint256 fresh = evidenceRegistry.registerReviewEvidence(receipt, corrections, caseId);
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = caseId;
        input.expectedTargetVersion = target;
        input.outcome = IAVACorrectionReview.Outcome.Withdrawn;
        input.finding = _findingInput(true);
        input.evidenceId = fresh;
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.reasonHash = REASON;
        requestVm.prank(VERIFIER_ACTOR);
        uint256 reviewId = corrections.review(input);
        require(
            corrections.findingIdByCase(caseId) == 1 && corrections.getFinding(1).independentReview,
            "Core procedural finding missing"
        );
        requestVm.expectRevert();
        corrections.getFinding(2);
        require(
            !registry.getRequest(id).paused && registry.getRequest(id).allocationDecisionId == positive,
            "Core review lost retained approval"
        );
        require(registry.constitutionalReviewIdByDecision(target) == reviewId, "missing Core review lineage");
        require(keccak256(abi.encode(registry.getDecision(target))) == oldDecision, "history rewritten");
        executor.execute(requestAllocation, execution, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(execution).completed, "retained approval cannot execute");
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        corrections.review(input);
    }

    function testCoreReviewNeutralChangedProcedureCannotRewindNewHead() public {
        _permitAll(ROLE_ALLOCATOR);
        uint256 id = _emptyRequest("Core changed procedure");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, 0);
        uint256 challenge = _file(target, _sourceEvidence());
        uint256 later = _procedure(id, IAVADecisionPolicy.Kind.SeekEvidence, target);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = adjudicator.correctionReviewCaseIdByChallenge(challenge);
        input.expectedTargetVersion = later;
        input.outcome = IAVACorrectionReview.Outcome.TargetChanged;
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.reasonHash = REASON;
        requestVm.prank(VERIFIER_ACTOR);
        corrections.review(input);
        require(
            registry.getRequest(id).paused && registry.getRequest(id).lastDecisionId == later,
            "neutral review rewound later procedure"
        );
        require(registry.procedureDisposition(target) == 0, "neutral review disposed target");
    }

    function testCoreReviewNeutralClosesVetoedCaseAfterSameHeadWithdrawal() public {
        adjudicator = new AVAProcedureAdjudication(registry, new RejectEveryProcedureResolution());
        _installProcedurePackage();
        _permitAll(ROLE_ALLOCATOR);
        (uint256 id, uint256 execution, uint256 positive) = _approved("Core same-head neutral closure");
        uint256 target = _procedure(id, IAVADecisionPolicy.Kind.Pause, positive);
        uint256 filingEvidence = _sourceEvidence();
        uint256 first = _file(target, filingEvidence);
        bytes32 source = _authority(ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        uint256 second = adjudicator.file(target, filingEvidence, ROLE_SOURCE, source, keccak256("second Core issue"));
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        uint256 firstCase = adjudicator.correctionReviewCaseIdByChallenge(first);
        uint256 secondCase = adjudicator.correctionReviewCaseIdByChallenge(second);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        IAVACorrectionReview.ReviewInput memory input;
        input.caseId = secondCase;
        input.expectedTargetVersion = target;
        input.outcome = IAVACorrectionReview.Outcome.TargetChanged;
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.reasonHash = REASON;
        _expectCoreReviewInvalidState(input);

        uint256 withdrawal;
        {
            AVAEvidenceRegistry.EvidenceRegistrationInput memory receipt =
                _receipt(ROLE_VERIFIER, _authority(ROLE_VERIFIER), requestPackageId);
            requestVm.prank(VERIFIER_ACTOR);
            uint256 fresh = evidenceRegistry.registerReviewEvidence(receipt, corrections, firstCase);
            input.caseId = firstCase;
            input.outcome = IAVACorrectionReview.Outcome.Withdrawn;
            input.evidenceId = fresh;
            input.finding = _findingInput(true);
            requestVm.prank(VERIFIER_ACTOR);
            withdrawal = corrections.review(input);
            input.caseId = secondCase;
            input.outcome = IAVACorrectionReview.Outcome.TargetChanged;
            _expectCoreReviewInvalidState(input);
            input.evidenceId = 0;
            _expectCoreReviewInvalidState(input);
            input.finding = _findingInput(false);
        }
        require(
            !registry.isProcedureCurrent(target) && registry.getRequest(id).lastDecisionId == target,
            "withdrawal did not preserve disposed head"
        );
        input.expectedTargetVersion = target + 1;
        _expectCoreReviewInvalidState(input);
        input.expectedTargetVersion = target;
        AVAProcedureAdjudication.ResolutionInput memory ordinary =
            _resolution(second, target, IAVAProcedurePolicy.Outcome.TargetChanged, 0);
        requestVm.prank(VERIFIER_ACTOR);
        ProcedureExactRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSignature("Error(string)", "all ordinary reviews vetoed"));
        adjudicator.resolve(ordinary);
        require(
            corrections.getCase(secondCase).reviewId == 0 && adjudicator.getChallenge(second).resolutionId == 0,
            "failed review closed pending case"
        );
        bytes32 pending = keccak256(abi.encode(registry.getRequest(id)));
        bytes32 history = keccak256(
            abi.encode(
                registry.getDecision(target),
                adjudicator.getResolution(adjudicator.getChallenge(first).resolutionId),
                corrections.getReview(withdrawal),
                corrections.getFinding(corrections.findingIdByCase(firstCase)),
                requestAllocation.getRequest(execution)
            )
        );
        bytes32 formation = keccak256(
            abi.encode(
                evidenceRegistry.nextEvidenceId(),
                kernel.CORRECTIONS().nextFindingId(),
                kernel.nextRecognisedStateId(),
                kernel.nextGovernedObjectId(),
                kernel.nextTransitionId()
            )
        );
        requestVm.prank(VERIFIER_ACTOR);
        uint256 reviewId = corrections.review(input);
        uint256 resolutionId = adjudicator.getChallenge(second).resolutionId;
        AVAProcedureAdjudication.Resolution memory resolution = adjudicator.getResolution(resolutionId);
        require(
            corrections.getCase(secondCase).reviewId == reviewId
                && adjudicator.constitutionalReviewIdByResolution(resolutionId) == reviewId
                && resolution.outcome == IAVAProcedurePolicy.Outcome.TargetChanged
                && resolution.currentDecisionId == target && resolution.replacementDecisionId == 0
                && resolution.decisionEvidenceId == 0 && corrections.getReview(reviewId).input.evidenceId == 0,
            "neutral closure missing retained lineage"
        );
        require(
            keccak256(abi.encode(registry.getRequest(id))) == pending
                && registry.procedureDisposition(target) == withdrawal
                && registry.constitutionalReviewIdByDecision(target) == withdrawal,
            "neutral closure changed pending controls or disposition"
        );
        require(
            keccak256(
                abi.encode(
                    registry.getDecision(target),
                    adjudicator.getResolution(adjudicator.getChallenge(first).resolutionId),
                    corrections.getReview(withdrawal),
                    corrections.getFinding(corrections.findingIdByCase(firstCase)),
                    requestAllocation.getRequest(execution)
                )
            ) == history,
            "neutral closure changed retained history"
        );
        require(
            corrections.findingIdByCase(secondCase) == 0
                && keccak256(
                    abi.encode(
                        evidenceRegistry.nextEvidenceId(),
                        kernel.CORRECTIONS().nextFindingId(),
                        kernel.nextRecognisedStateId(),
                        kernel.nextGovernedObjectId(),
                        kernel.nextTransitionId()
                    )
                ) == formation,
            "neutral closure manufactured evidence or recognition"
        );
        _expectCoreReviewInvalidState(input);
        _expectResolutionRevert(ordinary);
    }

    function _expectCoreReviewInvalidState(IAVACorrectionReview.ReviewInput memory input) internal {
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        requestVm.prank(VERIFIER_ACTOR);
        ProcedureExactRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, input.caseId));
        corrections.review(input);
    }

    function _installProcedurePackage() internal {
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(application);
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = new AVACoreRulePackageRegistry.ModuleBinding[](21);
        for (uint256 i; i < base.length; ++i) {
            bindings[i] = base[i];
        }
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(bridge));
        bindings[19] = _coreBinding(AVACapabilityKeys.DECISION_SET, address(policy));
        bindings[20] = _coreBinding(AVACapabilityKeys.PROCEDURE_REVIEW, address(adjudicator));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++version,
                keccak256("request.compatibility"),
                "test:procedure-rules"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
    }

    function _procedureOptions() internal pure returns (IAVADecisionPolicy.Option[] memory options) {
        options = new IAVADecisionPolicy.Option[](8);
        IAVADecisionPolicy.Option[] memory positives = _options(2, false, 0);
        options[0] = positives[0];
        options[1] = positives[1];
        for (uint256 i = 1; i <= 6; ++i) {
            IAVADecisionPolicy.Kind kind = IAVADecisionPolicy.Kind(i);
            options[i + 1] = IAVADecisionPolicy.Option(
                _key(kind), kind, _action(kind), keccak256(abi.encode("procedure parameters", kind)), 0, bytes32(0)
            );
        }
    }

    function _key(IAVADecisionPolicy.Kind kind) internal pure returns (bytes32) {
        return keccak256(abi.encode("procedure option", kind));
    }

    function _action(IAVADecisionPolicy.Kind kind) internal pure returns (bytes32) {
        return keccak256(abi.encode("procedure action", kind));
    }

    function _permit(bytes32 role, IAVADecisionPolicy.Kind kind, bool value) internal {
        authorityMatrix.setPermission(APP, role, _action(kind), value);
    }

    function _permitAll(bytes32 role) internal {
        for (uint256 i = 1; i <= 6; ++i) {
            _permit(role, IAVADecisionPolicy.Kind(i), true);
        }
    }

    function _emptyRequest(bytes32 hash) internal returns (uint256) {
        return _open(_input(hash), new IAVARequestPolicy.WitnessInput[](0));
    }

    function _procedure(uint256 id, IAVADecisionPolicy.Kind kind, uint256 previous) internal returns (uint256) {
        return _choose(id, _key(kind), 0, previous);
    }

    function _approved(bytes32 hash) internal returns (uint256 id, uint256 execution, uint256 positive) {
        IAVADecisionPolicy.Request memory input = _input(hash);
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        id = _open(input, pool);
        execution = _execution(input, pool, PARAMETERS);
        positive = _choose(id, POSITIVE, execution, 0);
    }

    function _receipt(bytes32 role, bytes32 subject, uint256 packageId)
        internal
        view
        returns (AVAEvidenceRegistry.EvidenceRegistrationInput memory)
    {
        return AVAEvidenceRegistry.EvidenceRegistrationInput(
            APP,
            REQUEST_WORKFLOW,
            packageId,
            role,
            subject,
            keccak256(abi.encode("procedure evidence", evidenceRegistry.nextEvidenceId())),
            keccak256("procedure review support"),
            requestPolicyId,
            subject,
            "test:procedure-evidence"
        );
    }

    function _evidence(address actor, bytes32 role, bytes32 subject, uint256 packageId) internal returns (uint256) {
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _receipt(role, subject, packageId);
        requestVm.prank(actor);
        return evidenceRegistry.registerEvidence(input);
    }

    function _sourceEvidence() internal returns (uint256) {
        return _evidence(SOURCE_ACTOR, ROLE_SOURCE, _authority(ROLE_SOURCE), requestPackageId);
    }

    function _resolverEvidence() internal returns (uint256) {
        return _evidence(VERIFIER_ACTOR, ROLE_VERIFIER, _authority(ROLE_VERIFIER), requestPackageId);
    }

    function _file(uint256 target, uint256 evidence) internal returns (uint256) {
        bytes32 authority = _authority(ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        return adjudicator.file(target, evidence, ROLE_SOURCE, authority, REASON);
    }

    function _revokeEvidence(uint256 evidence) internal {
        bytes32 authority = _authority(ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence, ROLE_SOURCE, authority, AVACoreTypes.EvidenceLifecycleKind.Revoke, 0, REASON, "test:revoke"
        );
    }

    function _resolution(uint256 challenge, uint256 head, IAVAProcedurePolicy.Outcome outcome, uint256 evidence)
        internal
        view
        returns (AVAProcedureAdjudication.ResolutionInput memory)
    {
        return AVAProcedureAdjudication.ResolutionInput(
            challenge,
            head,
            outcome,
            bytes32(0),
            evidence,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            REASON,
            _findingInput(
                outcome == IAVAProcedurePolicy.Outcome.Affirmed || outcome == IAVAProcedurePolicy.Outcome.Withdrawn
                    || outcome == IAVAProcedurePolicy.Outcome.Replaced
            )
        );
    }

    function _resolve(AVAProcedureAdjudication.ResolutionInput memory input) internal returns (uint256) {
        requestVm.prank(VERIFIER_ACTOR);
        return adjudicator.resolve(input);
    }

    function _expectResolutionRevert(AVAProcedureAdjudication.ResolutionInput memory input) internal {
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        adjudicator.resolve(input);
    }
}
