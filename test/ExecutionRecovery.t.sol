// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {IAVAExtensionPolicyModule} from "../src/extensions/shared/IAVAExtensionPolicyModule.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVAExecutionLifecycle, IAVAFencedSplitExecutor} from "../src/extensions/requests/AVAExecutionLifecycle.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface RecoveryExactVm {
    function expectRevert(bytes calldata reason) external;
}

/// @notice The only local effect path is invoked by the fixed execution helper.
contract FencedLocalEffect is IAVAFencedSplitExecutor {
    AVARequestAllocation public immutable ALLOCATION;
    bytes32 public configuration = keccak256("local.effect.configuration.v1");
    uint256 public effects;
    bool public fail;
    bool public zeroReceipt;

    constructor(AVARequestAllocation allocation) {
        ALLOCATION = allocation;
    }

    function fencedSplitInterfaceVersion() external pure returns (uint256) {
        return 1;
    }

    function fencedExecutionConfigurationHash() external view returns (bytes32) {
        return configuration;
    }

    function configure(bytes32 next, bool shouldFail) external {
        configuration = next;
        fail = shouldFail;
    }

    function configureReceipt(bool empty) external {
        zeroReceipt = empty;
    }

    function start(uint256 id, bytes32 response, bytes32 parameters) external returns (uint256) {
        return ALLOCATION.consumeSplit(id, response, parameters, msg.sender);
    }

    function recover(uint256 id, uint256 recoveryId) external returns (uint256) {
        return ALLOCATION.consumeRecovery(id, recoveryId, msg.sender);
    }

    function finish(uint256 id, uint256 attempt, bytes calldata data) external {
        ALLOCATION.completeAttempt(id, attempt, data);
    }

    function report(uint256 id, uint256 attempt, AVAExecutionLifecycle.ReportKind kind, bytes32 receipt)
        external
        returns (uint256)
    {
        return ALLOCATION.reportAttempt(id, attempt, kind, receipt);
    }

    function executeFencedEffect(uint256 id, uint256 attempt, bytes calldata data) external returns (bytes32) {
        require(msg.sender == address(ALLOCATION.EXECUTION()), "fixed execution helper");
        require(!fail, "local effect failed");
        effects += abi.decode(data, (uint256));
        if (zeroReceipt) return bytes32(0);
        return keccak256(abi.encode(id, attempt, effects));
    }
}

contract RejectRecoveryRestoration is IAVAExtensionPolicyModule, RuleModuleIdentity {
    function validateExtensionRecord(ExtensionPolicyContext calldata input) external pure {
        require(
            input.actionKey != keccak256("ava.extension.request.recovery.authorise.v1"), "recovery restoration veto"
        );
    }
}

contract ExecutionRecoveryTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("execution.recovery.app");
    bytes32 private constant RESPONSE = keccak256("execution.recovery.response");
    bytes32 private constant BURDEN = keccak256("execution.recovery.burden");
    bytes32 private constant REVIEW_ROLE = keccak256("execution.recovery.review.role");
    address private constant REVIEWER = address(0xD1);
    FencedLocalEffect private executor;
    bytes private effectData;

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("execution.object"));
        executor = new FencedLocalEffect(requestAllocation);
        effectData = abi.encode(uint256(1));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_AUTHORISE_RECOVERY(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        identityRegistry.assignSubject(REVIEWER, APP, REVIEW_ROLE, _authority(REVIEW_ROLE), "test:reviewer");
        authorityMatrix.setPermission(APP, REVIEW_ROLE, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
    }

    function testNoEffectFailureRecoversOnceAndAppliesOneRealEffect() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.configure(executor.configuration(), true);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 0, "failed effect rolled back");
        require(
            requestAllocation.getRequest(id).consumed && !requestAllocation.getRequest(id).completed,
            "consumption retained"
        );
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("failed"));
        uint256 recovery = _authorise(id, report);
        uint256 nextAttempt = executor.recover(id, recovery);
        executor.configure(executor.configuration(), false);
        executor.finish(id, nextAttempt, effectData);
        require(executor.effects() == 1, "one actual effect");
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.consumed && record.completed && record.effectHash != bytes32(0), "completed history");
        require(requestAllocation.EXECUTION().getAttempt(attempt).retired, "first attempt retained");
        require(requestAllocation.EXECUTION().getRecovery(recovery).used, "one-use recovery retained");
        // Operational reports, recovery authority and the actual retry do not form a substantive conclusion.
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        requestVm.expectRevert();
        corrections.getFinding(1);
        requestVm.expectRevert();
        executor.recover(id, recovery);
    }

    function testRetiredAttemptCannotApplyLateEffectOrCompleteThroughAtomicAbi() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        uint256 recovery = _authorise(id, report);
        uint256 nextAttempt = executor.recover(id, recovery);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        requestVm.expectRevert();
        requestVm.prank(address(executor));
        requestAllocation.complete(id, keccak256("unfenced completion"));
        require(executor.effects() == 0 && !requestAllocation.getRequest(id).completed, "late effect escaped fence");
        executor.finish(id, nextAttempt, effectData);
        require(executor.effects() == 1, "replacement actual effect");
    }

    function testInvalidCompletionReceiptRollsBackTheActualLocalEffect() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.configureReceipt(true);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 0, "local effect escaped receipt rollback");
        require(
            !requestAllocation.getRequest(id).completed && !requestAllocation.EXECUTION().getAttempt(attempt).completed,
            "failed completion retained"
        );
        executor.configureReceipt(false);
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 1, "live attempt effect missing");
    }

    function testLateContradictoryReportIsRetainedAndFreezesReplacementAttempt() public {
        uint256 id = _split();
        uint256 oldAttempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 failed =
            executor.report(id, oldAttempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        uint256 recovery = _authorise(id, failed);
        uint256 replacement = executor.recover(id, recovery);
        uint256 contradiction = executor.report(
            id, oldAttempt, AVAExecutionLifecycle.ReportKind.ContradictoryEffect, keccak256("late observed effect")
        );
        AVAExecutionLifecycle.Declaration memory declaration = requestAllocation.EXECUTION().getDeclaration(id);
        require(declaration.frozen && declaration.latestReportId == contradiction, "contradiction lost");
        require(requestAllocation.EXECUTION().getReport(contradiction).attemptId == oldAttempt, "late provenance lost");
        require(requestAllocation.EXECUTION().getAttempt(replacement).retired, "replacement not fenced");
        requestVm.expectRevert();
        executor.finish(id, replacement, effectData);
        require(executor.effects() == 0 && !requestAllocation.getRequest(id).completed, "frozen effect ran");
    }

    function testUnknownAndPartialEffectsCannotBeReclassifiedIntoRetry() public {
        _uncertainCannotRetry(AVAExecutionLifecycle.ReportKind.OutcomeUnknown);
        effectData = abi.encode(uint256(2));
        _uncertainCannotRetry(AVAExecutionLifecycle.ReportKind.PartialEffect);
    }

    function _uncertainCannotRetry(AVAExecutionLifecycle.ReportKind kind) private {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.report(id, attempt, kind, keccak256(abi.encode(kind)));
        uint256 latest =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("later assertion"));
        AVAExecutionLifecycle.RecoveryInput memory input = _recoveryInput(id, latest, _recoveryEvidence());
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.authoriseRecovery(input);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        require(requestAllocation.EXECUTION().getDeclaration(id).frozen, "uncertainty erased");
    }

    function testRecoveryRequiresLatestReportAndRejectsForeignAttempt() public {
        bytes memory originalParameters = effectData;
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 oldReport =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("first"));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("second"));
        AVAExecutionLifecycle.RecoveryInput memory input = _recoveryInput(id, oldReport, _recoveryEvidence());
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.authoriseRecovery(input);
        uint256 recovery = _authorise(id, report);
        effectData = abi.encode(uint256(2));
        uint256 other = _split();
        uint256 otherAttempt = executor.start(other, RESPONSE, keccak256(effectData));
        requestVm.expectRevert();
        executor.report(other, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("foreign"));
        requestVm.expectRevert();
        executor.finish(id, otherAttempt, originalParameters);
        requestVm.expectRevert();
        executor.recover(other, recovery);
        require(executor.effects() == 0, "foreign effect escaped");
    }

    function testAReportAfterAuthorisationInvalidatesThatRecovery() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("first"));
        uint256 recovery = _authorise(id, report);
        executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("new observation"));
        requestVm.expectRevert();
        executor.recover(id, recovery);
        require(!requestAllocation.EXECUTION().getRecovery(recovery).used, "stale recovery consumed");
    }

    function testCompletedAttemptWinsAgainstRecoveryAndCannotExecuteTwice() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.finish(id, attempt, effectData);
        uint256 report = executor.report(
            id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("contradictory no effect assertion")
        );
        AVAExecutionLifecycle.RecoveryInput memory input = _recoveryInput(id, report, _recoveryEvidence());
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.authoriseRecovery(input);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 1, "completion replayed");
    }

    function testRecoveryRechecksOriginalAllocatorPermission() public {
        (uint256 id, uint256 recovery) = _failedAndAuthorised();
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        executor.recover(id, recovery);
        require(!requestAllocation.EXECUTION().getRecovery(recovery).used, "invalid allocator recovery used");
        uint256 attempt = requestAllocation.EXECUTION().getRecovery(recovery).attemptId;
        uint256 report = executor.report(
            id, attempt, AVAExecutionLifecycle.ReportKind.OutcomeUnknown, keccak256("late after permission loss")
        );
        require(
            requestAllocation.EXECUTION().getReport(report).receiptHash == keccak256("late after permission loss"),
            "late report blocked"
        );
    }

    function testCompletionRequiresDeclaredExecutor() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        requestVm.expectRevert();
        requestAllocation.completeAttempt(id, attempt, effectData);
        require(executor.effects() == 0, "foreign caller invoked local effect");
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 1, "declared executor failed");
    }

    function testRecoveryReviewerPermissionIsLiveAtConsumptionAndCompletion() public {
        (uint256 id, uint256 recovery) = _failedAndAuthorised();
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_AUTHORISE_RECOVERY(), false);
        requestVm.expectRevert();
        executor.recover(id, recovery);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_AUTHORISE_RECOVERY(), true);
        uint256 attempt = executor.recover(id, recovery);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_AUTHORISE_RECOVERY(), false);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        require(executor.effects() == 0 && !requestAllocation.getRequest(id).completed, "revoked reviewer effect");
    }

    function testRecoveryExactDecisionEvidenceIsLiveAtConsumptionAndCompletion() public {
        (uint256 id, uint256 recovery) = _failedAndAuthorised();
        _revokeRecoveryEvidence(recovery);
        requestVm.expectRevert();
        executor.recover(id, recovery);
        effectData = abi.encode(uint256(2));
        (uint256 other, uint256 otherRecovery) = _failedAndAuthorised();
        uint256 attempt = executor.recover(other, otherRecovery);
        _revokeRecoveryEvidence(otherRecovery);
        requestVm.expectRevert();
        executor.finish(other, attempt, effectData);
        require(
            executor.effects() == 0 && !requestAllocation.getRequest(other).completed,
            "revoked decision evidence effect"
        );
    }

    function _revokeRecoveryEvidence(uint256 recovery) private {
        uint256 evidence = requestAllocation.EXECUTION().getRecovery(recovery).input.decisionEvidenceId;
        requestVm.prank(VERIFIER_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("revoke recovery review"),
            "test:revoke-recovery"
        );
    }

    function testRecoveryAndCompletionRecheckLiveSourceButLateReportsSurvive() public {
        (uint256 id, uint256 recovery) = _failedAndAuthorised();
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        requestVm.expectRevert();
        executor.recover(id, recovery);
        uint256 attempt = requestAllocation.EXECUTION().getRecovery(recovery).attemptId;
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.OutcomeUnknown, keccak256("late unknown"));
        require(
            requestAllocation.EXECUTION().getReport(report).receiptHash == keccak256("late unknown"),
            "late report blocked"
        );
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
    }

    function testRecoveryRejectsExpiredRequest() public {
        (uint256 id, uint256 recovery) = _failedAndAuthorised();
        requestVm.warp(requestAllocation.getRequest(id).input.validUntil);
        requestVm.expectRevert();
        executor.recover(id, recovery);
        require(!requestAllocation.EXECUTION().getRecovery(recovery).used, "expired recovery used");
    }

    function testSplitModeAndConsumedMeaningCannotSwitchToAtomicReplay() public {
        uint256 id = _split();
        requestVm.expectRevert();
        requestVm.prank(address(executor));
        requestAllocation.consume(id, RESPONSE, keccak256(effectData), address(this));
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        bytes32 configuration = executor.configuration();
        requestVm.expectRevert();
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.declareSplitMode(id, configuration);
        requestVm.warp(block.timestamp + 1);
        uint64 deadline = uint64(block.timestamp + 1 days);
        uint256 state = _createRequestState(address(executor), RESPONSE, keccak256(effectData), BURDEN, deadline);
        uint256 fresh = _createRequest(
            AVARequestAllocation.RequestInput(
                state, address(executor), RESPONSE, keccak256(effectData), BURDEN, deadline
            )
        );
        requestVm.expectRevert();
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.approve(fresh, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        require(
            requestAllocation.getRequest(id).consumed && !requestAllocation.getRequest(id).completed,
            "consumption was erased"
        );
    }

    function testExecutorCodeAndConfigurationStayPinnedAcrossAttempts() public {
        uint256 id = _split();
        bytes32 configuration = executor.configuration();
        executor.configure(keccak256("changed"), false);
        requestVm.expectRevert();
        executor.start(id, RESPONSE, keccak256(effectData));
        executor.configure(configuration, false);
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        executor.configure(keccak256("changed"), false);
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
        executor.configure(configuration, false);
        requestVm.etch(address(executor), hex"00");
        RecoveryExactVm(address(requestVm)).expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
        requestVm.prank(address(executor));
        requestAllocation.completeAttempt(id, attempt, effectData);
    }

    function testRecoveryReviewerMustBeIndependentFromOriginalAllocator() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, requestAllocation.ACTION_AUTHORISE_RECOVERY(), true);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        uint256 evidence = _evidence(ALLOCATOR_ACTOR, ROLE_ALLOCATOR);
        AVAExecutionLifecycle.RecoveryInput memory input = AVAExecutionLifecycle.RecoveryInput(
            id, report, evidence, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), keccak256("self review")
        );
        requestVm.expectRevert();
        requestVm.prank(ALLOCATOR_ACTOR);
        requestAllocation.authoriseRecovery(input);
    }

    function testHistoricalRestorationPolicyCanVetoRecovery() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _coreBindings(new M14PermissiveApplicationModule(APP));
        bindings[17] = _coreBinding(AVACapabilityKeys.RESTORATION, address(new RejectRecoveryRestoration()));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:recovery-veto"
            ),
            requestPackageId,
            bindings
        );
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        AVAExecutionLifecycle.RecoveryInput memory input = _recoveryInput(id, report, _recoveryEvidence());
        RecoveryExactVm(address(requestVm))
            .expectRevert(abi.encodeWithSignature("Error(string)", "recovery restoration veto"));
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.authoriseRecovery(input);
    }

    function testCoreReviewWithdrawsAcceptedAllocationAndPreservesActualReviewer() public {
        uint256 id = _split();
        uint256 challenge = _fileAllocation(id);
        uint256 caseId = requestAllocation.correctionReviewCaseIdByChallenge(challenge);
        uint256 evidence = _reviewEvidence(caseId);
        requestVm.expectRevert();
        requestAllocation.applyCorrectionReview(1);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        requestVm.prank(REVIEWER);
        corrections.review(
            IAVACorrectionReview.ReviewInput({
                caseId: caseId,
                expectedTargetVersion: 0,
                outcome: IAVACorrectionReview.Outcome.Withdrawn,
                evidenceId: evidence,
                roleKey: REVIEW_ROLE,
                authorityId: _authority(REVIEW_ROLE),
                reasonHash: keccak256("core allocation withdrawal"),
                asset: address(0),
                recipient: address(0),
                amount: 0,
                finding: _findingInput(true)
            })
        );
        require(corrections.findingIdByCase(caseId) == 1, "Core Allocation finding missing");
        requestVm.expectRevert();
        corrections.getFinding(2);
        AVARequestAllocation.RequestChallenge memory result = requestAllocation.getRequestChallenge(challenge);
        require(
            result.outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn && result.resolvedBy == REVIEWER,
            "review provenance"
        );
        require(!requestAllocation.getRequest(id).consumed, "review fabricated consumption");
        requestVm.expectRevert();
        executor.start(id, RESPONSE, keccak256(effectData));
    }

    function testCoreResidualDisposesPartialCaseWithoutFabricatingCompletion() public {
        uint256 id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.PartialEffect, keccak256("partial receipt"));
        uint256 challenge = _fileAllocation(id);
        uint256 caseId = requestAllocation.correctionReviewCaseIdByChallenge(challenge);
        uint256 evidence = _reviewEvidence(caseId);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        requestVm.prank(REVIEWER);
        corrections.review(
            IAVACorrectionReview.ReviewInput({
                caseId: caseId,
                expectedTargetVersion: 0,
                outcome: IAVACorrectionReview.Outcome.Residual,
                evidenceId: evidence,
                roleKey: REVIEW_ROLE,
                authorityId: _authority(REVIEW_ROLE),
                reasonHash: keccak256("partial effect reviewed residual"),
                asset: address(0),
                recipient: address(0),
                amount: 0,
                finding: _findingInput(true)
            })
        );
        require(
            requestAllocation.getRequestChallenge(challenge).outcome
                == AVARequestAllocation.ResolutionOutcome.ReviewedResidual,
            "residual review missing"
        );
        require(
            requestAllocation.EXECUTION().getReport(report).kind == AVAExecutionLifecycle.ReportKind.PartialEffect,
            "partial report changed"
        );
        require(
            requestAllocation.getRequest(id).consumed && !requestAllocation.getRequest(id).completed,
            "completion fabricated"
        );
        requestVm.expectRevert();
        executor.finish(id, attempt, effectData);
    }

    function _fileAllocation(uint256 id) private returns (uint256) {
        uint256 evidence = _evidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            keccak256("review allocation")
        );
    }

    function _reviewEvidence(uint256 caseId) private returns (uint256) {
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        requestVm.prank(REVIEWER);
        return evidenceRegistry.registerReviewEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: REVIEW_ROLE,
                subjectId: _authority(REVIEW_ROLE),
                commitment: keccak256(abi.encode("review", caseId)),
                evidenceTypeHash: keccak256("core review"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(REVIEW_ROLE),
                uri: "test:core-review"
            }),
            corrections,
            caseId
        );
    }

    function _failedAndAuthorised() private returns (uint256 id, uint256 recovery) {
        id = _split();
        uint256 attempt = executor.start(id, RESPONSE, keccak256(effectData));
        uint256 report =
            executor.report(id, attempt, AVAExecutionLifecycle.ReportKind.FailedNoEffect, keccak256("no effect"));
        recovery = _authorise(id, report);
    }

    function _split() private returns (uint256 id) {
        uint64 deadline = uint64(block.timestamp + 1 days);
        uint256 state = _createRequestState(address(executor), RESPONSE, keccak256(effectData), BURDEN, deadline);
        bytes32 configuration = executor.configuration();
        id = _createRequest(
            AVARequestAllocation.RequestInput(
                state, address(executor), RESPONSE, keccak256(effectData), BURDEN, deadline
            )
        );
        requestVm.prank(SOURCE_ACTOR);
        requestAllocation.declareSplitMode(id, configuration);
        _approveRequest(id);
    }

    function _authorise(uint256 id, uint256 report) private returns (uint256) {
        uint256 evidence = _recoveryEvidence();
        requestVm.prank(VERIFIER_ACTOR);
        return requestAllocation.authoriseRecovery(_recoveryInput(id, report, evidence));
    }

    function _recoveryInput(uint256 id, uint256 report, uint256 evidence)
        private
        view
        returns (AVAExecutionLifecycle.RecoveryInput memory)
    {
        return AVAExecutionLifecycle.RecoveryInput(
            id, report, evidence, ROLE_VERIFIER, _authority(ROLE_VERIFIER), keccak256("independent no effect review")
        );
    }

    function _recoveryEvidence() private returns (uint256) {
        return _evidence(VERIFIER_ACTOR, ROLE_VERIFIER);
    }

    function _evidence(address actor, bytes32 role) private returns (uint256) {
        uint256 nextId = evidenceRegistry.nextEvidenceId();
        requestVm.prank(actor);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: role,
                subjectId: _authority(role),
                commitment: keccak256(abi.encode("recovery evidence", nextId)),
                evidenceTypeHash: keccak256("execution.recovery.review"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(role),
                uri: "test:recovery"
            })
        );
    }
}
