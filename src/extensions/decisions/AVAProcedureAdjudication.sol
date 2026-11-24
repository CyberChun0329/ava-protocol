// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../../core/AVACapabilityKeys.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {
    IAVACorrectionReview,
    IAVAProcedureCorrectionReviewOrigin
} from "../../core/interfaces/IAVACorrectionReview.sol";
import {IAVADecisionPolicy} from "../../core/interfaces/IAVADecisionPolicy.sol";
import {IAVAProcedurePolicy} from "../../core/interfaces/IAVAProcedurePolicy.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {AVADecisionRegistry} from "./AVADecisionRegistry.sol";

/// @notice Append-only review of procedural Allocations, independent of live substantive support.
/// @dev Installed as PROCEDURE_REVIEW in the same historical package as its target request.
contract AVAProcedureAdjudication is RuleModuleIdentity, IAVAProcedureCorrectionReviewOrigin {
    struct Challenge {
        uint256 id;
        uint256 decisionId;
        uint256 requestId;
        address challenger;
        bytes32 challengerAuthorityId;
        uint256 evidenceId;
        bytes32 reasonHash;
        uint64 filedAt;
        uint256 resolutionId;
    }

    struct Resolution {
        uint256 id;
        uint256 challengeId;
        uint256 currentDecisionId;
        uint256 replacementDecisionId;
        IAVAProcedurePolicy.Outcome outcome;
        address resolver;
        bytes32 resolverAuthorityId;
        uint256 decisionEvidenceId;
        bytes32 replacementKey;
        bytes32 reasonHash;
        uint64 resolvedAt;
    }

    struct ResolutionInput {
        uint256 challengeId;
        uint256 expectedCurrentDecisionId;
        IAVAProcedurePolicy.Outcome outcome;
        bytes32 replacementKey;
        uint256 decisionEvidenceId;
        bytes32 roleKey;
        bytes32 authorityId;
        bytes32 reasonHash;
        IAVACorrectionReview.FindingInput finding;
    }
    AVADecisionRegistry public immutable DECISION_REGISTRY;
    IAVAProcedurePolicy public immutable REVIEW_POLICY;
    bytes32 public immutable REVIEW_POLICY_IDENTITY;
    mapping(uint256 => Challenge) private challenges;
    mapping(uint256 => Resolution) private resolutions;
    mapping(bytes32 => bool) private filedIssues;
    mapping(uint256 => uint256) public correctionReviewCaseIdByChallenge;
    mapping(uint256 => uint256) public constitutionalReviewIdByResolution;
    uint256 public nextChallengeId = 1;
    uint256 public nextResolutionId = 1;
    event ProcedureChallengeFiled(uint256 indexed challengeId, uint256 indexed decisionId, address actor);
    event ProcedureChallengeResolved(
        uint256 indexed resolutionId, uint256 indexed challengeId, IAVAProcedurePolicy.Outcome outcome
    );

    constructor(AVADecisionRegistry registry, IAVAProcedurePolicy policy) {
        if (address(registry).code.length == 0 || address(policy).code.length == 0) revert AVACoreTypes.EmptyValue();
        DECISION_REGISTRY = registry;
        REVIEW_POLICY = policy;
        REVIEW_POLICY_IDENTITY = policy.moduleIdentityHash();
    }

    function file(uint256 decisionId, uint256 evidenceId, bytes32 roleKey, bytes32 authorityId, bytes32 reasonHash)
        external
        returns (uint256 id)
    {
        AVADecisionRegistry.DecisionRecord memory target = DECISION_REGISTRY.getDecision(decisionId);
        AVADecisionRegistry.AtomicRequest memory request = DECISION_REGISTRY.getRequest(target.requestId);
        _bound(request.input.packageId);
        if (target.option.kind == IAVADecisionPolicy.Kind.Substantive || reasonHash == bytes32(0)) {
            revert AVACoreTypes.InvalidState(decisionId);
        }
        DECISION_REGISTRY.GOVERNANCE_KERNEL()
            .AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                msg.sender,
                request.input.appId,
                roleKey,
                DECISION_REGISTRY.ACTION_FILE_PROCEDURE_CHALLENGE(),
                authorityId
            );
        _decisionEvidence(evidenceId, request.input.packageId, authorityId);
        bytes32 issue = keccak256(abi.encode(decisionId, authorityId, evidenceId, reasonHash));
        if (filedIssues[issue]) revert AVACoreTypes.InvalidState(decisionId);
        filedIssues[issue] = true;
        id = nextChallengeId++;
        challenges[id] = Challenge(
            id,
            decisionId,
            target.requestId,
            msg.sender,
            authorityId,
            evidenceId,
            reasonHash,
            uint64(block.timestamp),
            0
        );
        _registerCorrectionCase(challenges[id], target, request);
        emit ProcedureChallengeFiled(id, decisionId, msg.sender);
    }

    function resolve(ResolutionInput calldata input) external returns (uint256 id) {
        Challenge storage challenge = challenges[input.challengeId];
        if (challenge.id == 0) revert AVACoreTypes.UnknownReference(input.challengeId);
        if (
            challenge.resolutionId != 0 || input.reasonHash == bytes32(0)
                || input.outcome == IAVAProcedurePolicy.Outcome.None
                || input.outcome == IAVAProcedurePolicy.Outcome.ReviewedResidual
        ) revert AVACoreTypes.InvalidState(challenge.id);
        AVADecisionRegistry.DecisionRecord memory target = DECISION_REGISTRY.getDecision(challenge.decisionId);
        AVADecisionRegistry.AtomicRequest memory request = DECISION_REGISTRY.getRequest(challenge.requestId);
        _bound(request.input.packageId);
        DECISION_REGISTRY.GOVERNANCE_KERNEL()
            .AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                msg.sender,
                request.input.appId,
                input.roleKey,
                DECISION_REGISTRY.ACTION_RESOLVE_PROCEDURE_CHALLENGE(),
                input.authorityId
            );
        if (request.lastDecisionId != input.expectedCurrentDecisionId) revert AVACoreTypes.InvalidState(request.id);
        bool current = DECISION_REGISTRY.isProcedureCurrent(target.id);
        if (input.outcome == IAVAProcedurePolicy.Outcome.TargetChanged) {
            if (current || input.decisionEvidenceId != 0) revert AVACoreTypes.InvalidState(challenge.id);
        } else if (input.outcome == IAVAProcedurePolicy.Outcome.EvidenceUnavailable) {
            if (_evidenceAvailable(challenge.evidenceId, request.input.packageId) || input.decisionEvidenceId != 0) {
                revert AVACoreTypes.InvalidState(challenge.id);
            }
        } else {
            _decisionEvidence(input.decisionEvidenceId, request.input.packageId, input.authorityId);
            if (
                (input.outcome == IAVAProcedurePolicy.Outcome.Withdrawn
                        || input.outcome == IAVAProcedurePolicy.Outcome.Replaced) && !current
            ) revert AVACoreTypes.InvalidState(challenge.id);
        }
        if ((input.outcome == IAVAProcedurePolicy.Outcome.Replaced) != (input.replacementKey != bytes32(0))) {
            revert AVACoreTypes.InvalidState(challenge.id);
        }
        REVIEW_POLICY.validateProcedureReview(
            IAVAProcedurePolicy.Review({
                appId: request.input.appId,
                workflowKey: request.input.workflowKey,
                packageId: request.input.packageId,
                requestId: request.id,
                decisionId: target.id,
                challengeId: challenge.id,
                currentDecisionId: request.lastDecisionId,
                originalActor: target.actor,
                challenger: challenge.challenger,
                resolver: msg.sender,
                roleKey: input.roleKey,
                authorityId: input.authorityId,
                decisionEvidenceId: input.decisionEvidenceId,
                outcome: input.outcome,
                replacementKey: input.replacementKey,
                reasonHash: input.reasonHash,
                evaluatedAt: uint64(block.timestamp)
            })
        );
        DECISION_REGISTRY.GOVERNANCE_KERNEL()
            .CORRECTIONS()
            .recordFinding(
                IAVACorrectionReview.FindingFormation({
                    caseId: correctionReviewCaseIdByChallenge[challenge.id],
                    targetVersion: input.expectedCurrentDecisionId,
                    evidenceId: input.decisionEvidenceId,
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    verifier: msg.sender,
                    substantive: input.outcome == IAVAProcedurePolicy.Outcome.Affirmed
                        || input.outcome == IAVAProcedurePolicy.Outcome.Withdrawn
                        || input.outcome == IAVAProcedurePolicy.Outcome.Replaced,
                    finding: input.finding
                })
            );
        id = nextResolutionId++;
        challenge.resolutionId = id;
        Resolution storage record = resolutions[id];
        record.id = id;
        record.challengeId = challenge.id;
        record.currentDecisionId = request.lastDecisionId;
        record.outcome = input.outcome;
        record.resolver = msg.sender;
        record.resolverAuthorityId = input.authorityId;
        record.decisionEvidenceId = input.decisionEvidenceId;
        record.replacementKey = input.replacementKey;
        record.reasonHash = input.reasonHash;
        record.resolvedAt = uint64(block.timestamp);
        if (
            input.outcome == IAVAProcedurePolicy.Outcome.Withdrawn
                || input.outcome == IAVAProcedurePolicy.Outcome.Replaced
        ) {
            record.replacementDecisionId = DECISION_REGISTRY.applyProcedureReview(
                AVADecisionRegistry.ProcedureApplication({
                    decisionId: target.id,
                    expectedCurrentDecisionId: request.lastDecisionId,
                    resolutionId: id,
                    outcome: input.outcome,
                    replacementKey: input.replacementKey,
                    resolver: msg.sender,
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    reasonHash: input.reasonHash
                })
            );
        }
        emit ProcedureChallengeResolved(id, challenge.id, input.outcome);
    }

    function GOVERNANCE_KERNEL() external view returns (AVAGovernanceKernel) {
        return DECISION_REGISTRY.GOVERNANCE_KERNEL();
    }

    function correctionTargetVersion(uint256 challengeId) external view returns (uint256) {
        Challenge storage challenge = challenges[challengeId];
        if (challenge.id == 0 || challenge.resolutionId != 0) revert AVACoreTypes.InvalidState(challengeId);
        return DECISION_REGISTRY.getRequest(challenge.requestId).lastDecisionId;
    }

    function correctionTargetCurrent(uint256 challengeId) external view returns (bool) {
        Challenge storage challenge = challenges[challengeId];
        if (challenge.id == 0 || challenge.resolutionId != 0) revert AVACoreTypes.InvalidState(challengeId);
        return DECISION_REGISTRY.isProcedureCurrent(challenge.decisionId);
    }

    function applyCorrectionReview(uint256 reviewId) external {
        IAVACorrectionReview registry =
            IAVACorrectionReview(address(DECISION_REGISTRY.GOVERNANCE_KERNEL().CORRECTIONS()));
        if (msg.sender != address(registry)) {
            revert AVACoreTypes.InvalidState(reviewId);
        }
        IAVACorrectionReview.Disposition memory review = registry.activeDisposition(reviewId);
        Challenge storage challenge = challenges[review.originCaseId];
        if (challenge.id == 0 || challenge.resolutionId != 0) revert AVACoreTypes.InvalidState(reviewId);
        AVADecisionRegistry.AtomicRequest memory request = DECISION_REGISTRY.getRequest(challenge.requestId);
        if (request.lastDecisionId != review.expectedTargetVersion) revert AVACoreTypes.InvalidState(reviewId);
        IAVAProcedurePolicy.Outcome outcome;
        if (review.outcome == IAVACorrectionReview.Outcome.Withdrawn) {
            outcome = IAVAProcedurePolicy.Outcome.Withdrawn;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Affirmed) {
            outcome = IAVAProcedurePolicy.Outcome.Affirmed;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Residual) {
            outcome = IAVAProcedurePolicy.Outcome.ReviewedResidual;
        } else if (review.outcome == IAVACorrectionReview.Outcome.EvidenceUnavailable) {
            outcome = IAVAProcedurePolicy.Outcome.EvidenceUnavailable;
        } else if (review.outcome == IAVACorrectionReview.Outcome.TargetChanged) {
            outcome = IAVAProcedurePolicy.Outcome.TargetChanged;
        } else {
            revert AVACoreTypes.InvalidState(reviewId);
        }
        uint256 id = nextResolutionId++;
        challenge.resolutionId = id;
        resolutions[id] = Resolution(
            id,
            challenge.id,
            request.lastDecisionId,
            0,
            outcome,
            review.actor,
            review.authorityId,
            review.evidenceId,
            bytes32(0),
            review.reasonHash,
            uint64(block.timestamp)
        );
        constitutionalReviewIdByResolution[id] = reviewId;
        if (outcome == IAVAProcedurePolicy.Outcome.Withdrawn) {
            DECISION_REGISTRY.applyCorrectionReviewWithdrawal(challenge.decisionId, reviewId);
        }
        emit ProcedureChallengeResolved(id, challenge.id, outcome);
    }

    function _registerCorrectionCase(
        Challenge storage challenge,
        AVADecisionRegistry.DecisionRecord memory target,
        AVADecisionRegistry.AtomicRequest memory request
    ) private {
        IAVACorrectionReview.CaseInput memory input;
        input.kind = IAVACorrectionReview.TargetKind.Procedure;
        input.appId = request.input.appId;
        input.workflowKey = request.input.workflowKey;
        input.packageId = request.input.packageId;
        input.targetPackageId = request.input.packageId;
        input.originCaseId = challenge.id;
        input.targetId = target.id;
        input.originalTargetVersion = request.lastDecisionId;
        input.filingEvidenceId = challenge.evidenceId;
        input.challengerSubjectId = challenge.challengerAuthorityId;
        input.originalActor = target.actor;
        input.challenger = challenge.challenger;
        input.affectedActor = request.input.executor;
        uint256 id = DECISION_REGISTRY.GOVERNANCE_KERNEL().CORRECTIONS().registerCase(input);
        correctionReviewCaseIdByChallenge[challenge.id] = id;
    }

    function getChallenge(uint256 id) external view returns (Challenge memory) {
        if (challenges[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return challenges[id];
    }

    function getResolution(uint256 id) external view returns (Resolution memory) {
        if (resolutions[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return resolutions[id];
    }

    function _bound(uint256 packageId) private view {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.PROCEDURE_REVIEW;
        (, address[] memory modules) =
            DECISION_REGISTRY.GOVERNANCE_KERNEL().RULE_PACKAGE_REGISTRY().getVerifiedModulesCompact(packageId, keys);
        if (modules[0] != address(this) || REVIEW_POLICY.moduleIdentityHash() != REVIEW_POLICY_IDENTITY) {
            revert AVACoreTypes.InvalidState(packageId);
        }
    }

    function _decisionEvidence(uint256 evidenceId, uint256 packageId, bytes32 authorityId) private view {
        AVAEvidenceRegistry evidence = DECISION_REGISTRY.GOVERNANCE_KERNEL().EVIDENCE_REGISTRY();
        evidence.requireUsableCorrectionEvidenceReferenceForPackage(evidenceId, packageId);
        if (evidence.getEvidenceReference(evidenceId).subjectId != authorityId) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
    }

    function _evidenceAvailable(uint256 evidenceId, uint256 packageId) private view returns (bool) {
        AVAEvidenceRegistry evidence = DECISION_REGISTRY.GOVERNANCE_KERNEL().EVIDENCE_REGISTRY();
        if (!evidence.isEvidenceAvailableForPackage(evidenceId, packageId)) return false;
        evidence.requireUsableCorrectionEvidenceReferenceForPackage(evidenceId, packageId);
        return true;
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(address(DECISION_REGISTRY), address(REVIEW_POLICY), REVIEW_POLICY_IDENTITY));
    }
}
