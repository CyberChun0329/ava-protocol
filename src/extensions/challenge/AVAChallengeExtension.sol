// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVAAuthorityMatrix} from "../../core/AVAAuthorityMatrix.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVACoreTransitionRules} from "../../core/AVACoreTransitionRules.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVAIdentityRegistry} from "../../core/AVAIdentityRegistry.sol";
import {AVAWorkflowPolicyRouter} from "../../core/AVAWorkflowPolicyRouter.sol";
import {IAVATransitionGuard} from "../../core/interfaces/IAVATransitionGuard.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {IAVACorrectionReview} from "../../core/interfaces/IAVACorrectionReview.sol";
import {AVAChallengePolicyValidation} from "./AVAChallengePolicyValidation.sol";

contract AVAChallengeExtension is IAVATransitionGuard, RuleModuleIdentity {
    enum ChallengeStatus {
        None,
        ConcernFiled,
        AdmissibilityScreening,
        Resolved,
        RestorationAvailable,
        Closed
    }

    enum ChallengeOutcome {
        None,
        Upheld,
        RejectedGoodFaith,
        Negligent,
        MaliciousOrFabricated,
        Unavailable,
        TargetChangedNoReversal,
        ReviewAffirmed,
        ReviewResidual
    }

    enum ChallengeTransitionKind {
        None,
        Filing,
        Screening,
        Resolution,
        RestorationAvailability,
        Restoration,
        Closure
    }

    struct ChallengeFilingInput {
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        uint256 challengeRecognisedStateId;
        uint256 challengedRecognisedStateId;
        bytes32 roleKey;
        bytes32 reasonHash;
        string reasonURI;
    }

    struct ChallengeResolutionInput {
        uint256 challengeId;
        bytes32 roleKey;
        bytes32 authorityId;
        ChallengeOutcome outcome;
        AVACoreTypes.RecognisedStateStatus correctionStatus;
        bytes32 reasonHash;
        string reasonURI;
        IAVACorrectionReview.FindingInput finding;
    }

    struct ChallengeRecord {
        uint256 id;
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        uint256 targetPackageId;
        uint256 challengeGovernedObjectId;
        uint256 challengeRecognisedStateId;
        uint256 challengedRecognisedStateId;
        bytes32 challengerSubjectId;
        uint256 evidenceReceiptId;
        uint256 disclosurePolicyId;
        AVACoreTypes.RecognisedStateStatus targetStatusAtFiling;
        uint256 targetTransitionIdAtFiling;
        uint256 targetTransitionIdAfterResolution;
        uint256 challengeStateTransitionIdAtFiling;
        uint256 challengeStateTransitionIdAfterResolution;
        ChallengeStatus status;
        ChallengeOutcome outcome;
        uint256 lastTransitionId;
        address filedBy;
        uint64 filedAt;
        uint256 decisionEvidenceReceiptId;
    }

    struct ChallengeTransitionRecord {
        uint256 id;
        uint256 challengeId;
        bytes32 appId;
        uint256 packageId;
        uint256 targetPackageId;
        uint256 challengeRecognisedStateId;
        uint256 challengedRecognisedStateId;
        ChallengeTransitionKind kind;
        ChallengeStatus fromStatus;
        ChallengeStatus toStatus;
        ChallengeOutcome outcome;
        uint256 challengeStateTransitionIdBefore;
        uint256 challengeStateTransitionIdAfter;
        uint256 targetTransitionIdBefore;
        uint256 targetTransitionIdAfter;
        uint256 evidenceReceiptId;
        bytes32 authorityId;
        bytes32 reasonHash;
        string reasonURI;
        address createdBy;
        uint64 createdAt;
        uint256 decisionEvidenceReceiptId;
    }

    struct TransitionWriteInput {
        ChallengeTransitionKind kind;
        ChallengeStatus fromStatus;
        ChallengeStatus toStatus;
        ChallengeOutcome outcome;
        uint256 challengeStateTransitionIdBefore;
        uint256 challengeStateTransitionIdAfter;
        uint256 targetTransitionIdBefore;
        uint256 targetTransitionIdAfter;
        bytes32 authorityId;
        bytes32 reasonHash;
        string reasonURI;
        address actor;
    }

    struct StoredPolicyInput {
        bytes32 actionKey;
        bytes32 roleKey;
        bytes32 authorityId;
        ChallengeOutcome outcome;
        bytes32 reasonHash;
        address authorityActor;
    }

    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    AVAAuthorityMatrix public immutable AUTHORITY_MATRIX;
    AVAIdentityRegistry public immutable IDENTITY_REGISTRY;
    AVACoreRulePackageRegistry public immutable RULE_PACKAGE_REGISTRY;
    AVAEvidenceRegistry public immutable EVIDENCE_REGISTRY;
    AVAWorkflowPolicyRouter public immutable POLICY_ROUTER;

    mapping(uint256 => ChallengeRecord) private challenges;
    mapping(uint256 => ChallengeTransitionRecord) private transitions;
    mapping(uint256 => uint256) public openChallengeCountByRecognisedState;
    mapping(uint256 => uint256) public challengeIdByRecognisedState;
    mapping(uint256 => bool) private decisionBoundChallengeState;
    mapping(bytes32 => bool) private filingKeyUsed;
    mapping(uint256 => uint256) public correctionReviewCaseIdByChallenge;
    uint256 public nextChallengeId = 1;
    uint256 public nextTransitionId = 1;
    uint256 private lifecycleEntered;

    event ChallengeFiled(
        uint256 indexed challengeId,
        bytes32 indexed appId,
        uint256 indexed challengedRecognisedStateId,
        uint256 challengeRecognisedStateId,
        uint256 packageId,
        uint256 targetPackageId,
        bytes32 challengerSubjectId,
        uint256 evidenceReceiptId,
        address filedBy
    );
    event ChallengeTransitionRecorded(
        uint256 indexed transitionId,
        uint256 indexed challengeId,
        ChallengeTransitionKind indexed kind,
        ChallengeStatus fromStatus,
        ChallengeStatus toStatus,
        ChallengeOutcome outcome,
        uint256 targetTransitionIdAfter,
        bytes32 authorityId,
        address createdBy
    );

    constructor(
        AVAGovernanceKernel governanceKernel_,
        AVAAuthorityMatrix authorityMatrix_,
        AVAIdentityRegistry identityRegistry_,
        AVACoreRulePackageRegistry rulePackageRegistry_,
        AVAEvidenceRegistry evidenceRegistry_
    ) {
        if (
            address(governanceKernel_) == address(0) || address(authorityMatrix_) == address(0)
                || address(identityRegistry_) == address(0) || address(rulePackageRegistry_) == address(0)
                || address(evidenceRegistry_) == address(0)
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        if (
            address(governanceKernel_.AUTHORITY_MATRIX()) != address(authorityMatrix_)
                || address(governanceKernel_.IDENTITY_REGISTRY()) != address(identityRegistry_)
                || address(governanceKernel_.RULE_PACKAGE_REGISTRY()) != address(rulePackageRegistry_)
                || address(governanceKernel_.EVIDENCE_REGISTRY()) != address(evidenceRegistry_)
        ) {
            revert AVACoreTypes.InvalidState(0);
        }
        GOVERNANCE_KERNEL = governanceKernel_;
        AUTHORITY_MATRIX = authorityMatrix_;
        IDENTITY_REGISTRY = identityRegistry_;
        RULE_PACKAGE_REGISTRY = rulePackageRegistry_;
        EVIDENCE_REGISTRY = evidenceRegistry_;
        POLICY_ROUTER = governanceKernel_.POLICY_ROUTER();
    }

    modifier nonReentrantLifecycle() {
        _enterLifecycle();
        _;
        _exitLifecycle();
    }

    function _enterLifecycle() private {
        if (lifecycleEntered != 0) revert AVACoreTypes.InvalidState(0);
        lifecycleEntered = 1;
    }

    function _exitLifecycle() private {
        lifecycleEntered = 0;
    }

    function fileChallenge(ChallengeFilingInput calldata input)
        external
        nonReentrantLifecycle
        returns (uint256 challengeId)
    {
        if (
            input.appId == bytes32(0) || input.workflowKey == bytes32(0) || input.packageId == 0
                || input.challengeRecognisedStateId == 0 || input.challengedRecognisedStateId == 0
                || input.roleKey == bytes32(0) || input.reasonHash == bytes32(0)
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        (
            AVAGovernanceKernel.RecognisedStateReference memory challengeState,
            AVAGovernanceKernel.GovernedObjectReference memory challengeObject,
            AVAGovernanceKernel.RecognisedStateReference memory target
        ) = _validateChallengeFiling(input);
        bytes32 filingKey =
            _filingKey(input.appId, input.challengedRecognisedStateId, target.lastTransitionId, msg.sender);
        if (filingKeyUsed[filingKey] || challengeIdByRecognisedState[challengeState.id] != 0) {
            revert AVACoreTypes.InvalidState(input.challengedRecognisedStateId);
        }
        filingKeyUsed[filingKey] = true;

        challengeId = nextChallengeId++;
        challenges[challengeId] = ChallengeRecord({
            id: challengeId,
            appId: input.appId,
            workflowKey: input.workflowKey,
            packageId: input.packageId,
            targetPackageId: target.packageId,
            challengeGovernedObjectId: challengeObject.id,
            challengeRecognisedStateId: challengeState.id,
            challengedRecognisedStateId: input.challengedRecognisedStateId,
            challengerSubjectId: challengeState.subjectId,
            evidenceReceiptId: challengeState.evidenceReceiptId,
            disclosurePolicyId: challengeState.disclosurePolicyId,
            targetStatusAtFiling: target.status,
            targetTransitionIdAtFiling: target.lastTransitionId,
            targetTransitionIdAfterResolution: 0,
            challengeStateTransitionIdAtFiling: 0,
            challengeStateTransitionIdAfterResolution: 0,
            status: ChallengeStatus.ConcernFiled,
            outcome: ChallengeOutcome.None,
            lastTransitionId: 0,
            filedBy: msg.sender,
            filedAt: uint64(block.timestamp),
            decisionEvidenceReceiptId: 0
        });
        challengeIdByRecognisedState[challengeState.id] = challengeId;
        decisionBoundChallengeState[challengeState.id] = true;
        uint256 challengeStateTransitionId =
            _requestChallengeFilingTransition(challenges[challengeId], challengeState, target, input);
        challenges[challengeId].challengeStateTransitionIdAtFiling = challengeStateTransitionId;
        challenges[challengeId].challengeStateTransitionIdAfterResolution = challengeStateTransitionId;
        openChallengeCountByRecognisedState[input.challengedRecognisedStateId]++;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.Filing;
        writeInput.fromStatus = ChallengeStatus.None;
        writeInput.toStatus = ChallengeStatus.ConcernFiled;
        writeInput.outcome = ChallengeOutcome.None;
        writeInput.challengeStateTransitionIdBefore = challengeState.lastTransitionId;
        writeInput.challengeStateTransitionIdAfter = challengeStateTransitionId;
        writeInput.targetTransitionIdBefore = target.lastTransitionId;
        writeInput.targetTransitionIdAfter = target.lastTransitionId;
        writeInput.authorityId = challengeState.subjectId;
        writeInput.reasonHash = input.reasonHash;
        writeInput.reasonURI = input.reasonURI;
        writeInput.actor = msg.sender;
        uint256 transitionId = _recordTransition(challenges[challengeId], writeInput);
        challenges[challengeId].lastTransitionId = transitionId;
        emit ChallengeFiled(
            challengeId,
            input.appId,
            input.challengedRecognisedStateId,
            input.challengeRecognisedStateId,
            input.packageId,
            target.packageId,
            challengeState.subjectId,
            challengeState.evidenceReceiptId,
            msg.sender
        );
    }

    function screenChallenge(uint256 challengeId, bytes32 roleKey, bytes32 authorityId)
        external
        nonReentrantLifecycle
        returns (uint256 transitionId)
    {
        ChallengeRecord storage challenge = _challengeStorage(challengeId);
        if (challenge.status != ChallengeStatus.ConcernFiled) revert AVACoreTypes.InvalidState(challengeId);
        _requireStoredChallengeEvidence(challenge);
        address authorityActor =
            _requireNonConflictedAuthority(challenge, roleKey, AVACoreTypes.ACTION_SCREEN_CHALLENGE, authorityId);
        bytes32 screeningReasonHash = keccak256(abi.encode("challenge-screening", challengeId));
        _validateStoredChallengePolicies(
            challenge,
            StoredPolicyInput({
                actionKey: AVACoreTypes.ACTION_SCREEN_CHALLENGE,
                roleKey: roleKey,
                authorityId: authorityId,
                outcome: ChallengeOutcome.None,
                reasonHash: screeningReasonHash,
                authorityActor: authorityActor
            })
        );
        ChallengeStatus fromStatus = challenge.status;
        challenge.status = ChallengeStatus.AdmissibilityScreening;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.Screening;
        writeInput.fromStatus = fromStatus;
        writeInput.toStatus = challenge.status;
        writeInput.outcome = ChallengeOutcome.None;
        writeInput.challengeStateTransitionIdBefore = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.challengeStateTransitionIdAfter = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.targetTransitionIdBefore = challenge.targetTransitionIdAtFiling;
        writeInput.targetTransitionIdAfter = challenge.targetTransitionIdAtFiling;
        writeInput.authorityId = authorityId;
        writeInput.reasonHash = screeningReasonHash;
        writeInput.actor = authorityActor;
        transitionId = _recordTransition(challenge, writeInput);
        challenge.lastTransitionId = transitionId;
        _registerCorrectionCase(challenge);
    }

    function resolveChallenge(ChallengeResolutionInput calldata input)
        external
        nonReentrantLifecycle
        returns (uint256 transitionId)
    {
        uint256 evidenceId = input.outcome == ChallengeOutcome.Unavailable
            ? 0
            : _challengeStorage(input.challengeId).evidenceReceiptId;
        return _resolveChallenge(input, evidenceId);
    }

    /// @notice Selects current decision support without replacing the original filing receipt.
    function resolveChallengeWithEvidence(ChallengeResolutionInput calldata input, uint256 decisionEvidenceReceiptId)
        external
        nonReentrantLifecycle
        returns (uint256 transitionId)
    {
        return _resolveChallenge(input, decisionEvidenceReceiptId);
    }

    function _resolveChallenge(ChallengeResolutionInput calldata input, uint256 decisionEvidenceReceiptId)
        private
        returns (uint256 transitionId)
    {
        ChallengeRecord storage challenge = _challengeStorage(input.challengeId);
        bool nonMerits =
            input.outcome == ChallengeOutcome.Unavailable || input.outcome == ChallengeOutcome.TargetChangedNoReversal;
        if (
            (challenge.status != ChallengeStatus.AdmissibilityScreening
                    && !(nonMerits && challenge.status == ChallengeStatus.ConcernFiled))
                || input.outcome == ChallengeOutcome.None || input.outcome >= ChallengeOutcome.ReviewAffirmed
                || input.reasonHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(input.challengeId);
        }
        if (input.outcome == ChallengeOutcome.Unavailable) {
            if (decisionEvidenceReceiptId != 0 || !_filingUnavailable(challenge)) {
                revert AVACoreTypes.InvalidState(input.challengeId);
            }
        } else {
            _requireDecisionEvidence(challenge, decisionEvidenceReceiptId);
        }
        address authorityActor = _requireNonConflictedAuthority(
            challenge, input.roleKey, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, input.authorityId
        );
        AVAGovernanceKernel.RecognisedStateReference memory target =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId);
        if (
            input.outcome == ChallengeOutcome.TargetChangedNoReversal
                && target.lastTransitionId == challenge.targetTransitionIdAtFiling
        ) revert AVACoreTypes.InvalidState(input.challengeId);
        challenge.decisionEvidenceReceiptId = decisionEvidenceReceiptId;
        _validateStoredChallengePolicies(
            challenge,
            StoredPolicyInput({
                actionKey: AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                roleKey: input.roleKey,
                authorityId: input.authorityId,
                outcome: input.outcome,
                reasonHash: input.reasonHash,
                authorityActor: authorityActor
            })
        );
        GOVERNANCE_KERNEL.CORRECTIONS()
            .recordFinding(
                IAVACorrectionReview.FindingFormation({
                    caseId: correctionReviewCaseIdByChallenge[challenge.id],
                    targetVersion: target.lastTransitionId,
                    evidenceId: decisionEvidenceReceiptId,
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    verifier: authorityActor,
                    substantive: !nonMerits,
                    finding: input.finding
                })
            );
        uint256 transitionIdBefore = target.lastTransitionId;
        uint256 transitionIdAfter = transitionIdBefore;
        AVAGovernanceKernel.RecognisedStateReference memory challengeState =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengeRecognisedStateId);
        challenge.challengeStateTransitionIdAfterResolution = challengeState.lastTransitionId;
        bytes32 decisionHash = _decisionHash(
            challenge.id,
            AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
            transitionIdBefore,
            input.outcome,
            input.reasonHash,
            challenge.packageId,
            challenge.targetPackageId
        );
        if (input.outcome == ChallengeOutcome.Upheld) {
            if (
                transitionIdBefore != challenge.targetTransitionIdAtFiling
                    || (input.correctionStatus != AVACoreTypes.RecognisedStateStatus.Downgraded
                        && input.correctionStatus != AVACoreTypes.RecognisedStateStatus.Voided)
            ) {
                revert AVACoreTypes.InvalidState(input.challengeId);
            }
            transitionIdAfter = GOVERNANCE_KERNEL.requestSourceBoundTransition(
                AVAGovernanceKernel.SourceBoundTransitionInput({
                    recognisedStateId: challenge.challengedRecognisedStateId,
                    expectedTransitionId: transitionIdBefore,
                    decisionPackageId: challenge.packageId,
                    sourceRecordId: challenge.id,
                    decisionEvidenceReceiptId: decisionEvidenceReceiptId,
                    disclosureTargetId: challenge.challengedRecognisedStateId,
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    actionKey: AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                    decisionHash: decisionHash,
                    toStatus: input.correctionStatus,
                    kind: AVACoreTypes.TransitionKind.ChallengeCorrection,
                    reasonHash: input.reasonHash,
                    reasonURI: input.reasonURI
                })
            );
        } else if (input.correctionStatus != target.status) {
            revert AVACoreTypes.InvalidState(input.challengeId);
        }

        ChallengeStatus fromStatus = challenge.status;
        challenge.status = ChallengeStatus.Resolved;
        challenge.outcome = input.outcome;
        challenge.targetTransitionIdAfterResolution = transitionIdAfter;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.Resolution;
        writeInput.fromStatus = fromStatus;
        writeInput.toStatus = challenge.status;
        writeInput.outcome = input.outcome;
        writeInput.challengeStateTransitionIdBefore = challengeState.lastTransitionId;
        writeInput.challengeStateTransitionIdAfter = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.targetTransitionIdBefore = transitionIdBefore;
        writeInput.targetTransitionIdAfter = transitionIdAfter;
        writeInput.authorityId = input.authorityId;
        writeInput.reasonHash = input.reasonHash;
        writeInput.reasonURI = input.reasonURI;
        writeInput.actor = authorityActor;
        transitionId = _recordTransition(challenge, writeInput);
        challenge.lastTransitionId = transitionId;
    }

    function recordRestorationAvailability(
        uint256 challengeId,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 reasonHash,
        string calldata reasonURI
    ) external nonReentrantLifecycle returns (uint256 transitionId) {
        ChallengeRecord storage challenge = _challengeStorage(challengeId);
        if (
            challenge.status != ChallengeStatus.Resolved || !_isRestorableOutcome(challenge.outcome)
                || reasonHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        _requireDecisionEvidence(challenge, challenge.decisionEvidenceReceiptId);
        address authorityActor =
            _requireNonConflictedAuthority(challenge, roleKey, AVACoreTypes.ACTION_APPLY_RESTORATION, authorityId);
        _validateStoredChallengePolicies(
            challenge,
            StoredPolicyInput({
                actionKey: AVACoreTypes.ACTION_APPLY_RESTORATION,
                roleKey: roleKey,
                authorityId: authorityId,
                outcome: challenge.outcome,
                reasonHash: reasonHash,
                authorityActor: authorityActor
            })
        );
        AVAGovernanceKernel.RecognisedStateReference memory target =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId);
        if (target.lastTransitionId != challenge.targetTransitionIdAfterResolution) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        _requireRestorationLineage(challenge, target);
        if (target.status != _restorationStatus(challenge.targetStatusAtFiling)) {
            // A fresh correction finding cannot reactivate the target's terminally lost basis.
            // Check these current prerequisites before advertising restoration; apply rechecks them.
            IDENTITY_REGISTRY.requireActiveSubjectReference(target.subjectId, target.appId);
            EVIDENCE_REGISTRY.requireUsableEvidenceReferenceForPackage(target.evidenceReceiptId, target.packageId);
        }
        uint256 targetTransitionId = target.lastTransitionId;
        ChallengeStatus fromStatus = challenge.status;
        challenge.status = ChallengeStatus.RestorationAvailable;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.RestorationAvailability;
        writeInput.fromStatus = fromStatus;
        writeInput.toStatus = challenge.status;
        writeInput.outcome = challenge.outcome;
        writeInput.challengeStateTransitionIdBefore = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.challengeStateTransitionIdAfter = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.targetTransitionIdBefore = targetTransitionId;
        writeInput.targetTransitionIdAfter = targetTransitionId;
        writeInput.authorityId = authorityId;
        writeInput.reasonHash = reasonHash;
        writeInput.reasonURI = reasonURI;
        writeInput.actor = authorityActor;
        transitionId = _recordTransition(challenge, writeInput);
        challenge.lastTransitionId = transitionId;
    }

    function applyRestoration(
        uint256 challengeId,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 reasonHash,
        string calldata reasonURI
    ) external nonReentrantLifecycle returns (uint256 transitionId) {
        ChallengeRecord storage challenge = _challengeStorage(challengeId);
        if (
            challenge.status != ChallengeStatus.RestorationAvailable || !_isRestorableOutcome(challenge.outcome)
                || reasonHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        _requireDecisionEvidence(challenge, challenge.decisionEvidenceReceiptId);
        address authorityActor =
            _requireNonConflictedAuthority(challenge, roleKey, AVACoreTypes.ACTION_APPLY_RESTORATION, authorityId);
        _validateStoredChallengePolicies(
            challenge,
            StoredPolicyInput({
                actionKey: AVACoreTypes.ACTION_APPLY_RESTORATION,
                roleKey: roleKey,
                authorityId: authorityId,
                outcome: challenge.outcome,
                reasonHash: reasonHash,
                authorityActor: authorityActor
            })
        );
        AVAGovernanceKernel.RecognisedStateReference memory target =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId);
        if (target.lastTransitionId != challenge.targetTransitionIdAfterResolution) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        AVACoreTypes.RecognisedStateStatus restorationStatus = _restorationStatus(challenge.targetStatusAtFiling);
        _requireRestorationLineage(challenge, target);
        uint256 restorationTransitionId = target.lastTransitionId;
        if (target.status != restorationStatus) {
            restorationTransitionId = _requestRestorationTransition(
                challenge, target, roleKey, authorityId, restorationStatus, reasonHash, reasonURI
            );
        }
        ChallengeStatus fromStatus = challenge.status;
        challenge.status = ChallengeStatus.Closed;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.Restoration;
        writeInput.fromStatus = fromStatus;
        writeInput.toStatus = challenge.status;
        writeInput.outcome = challenge.outcome;
        writeInput.challengeStateTransitionIdBefore = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.challengeStateTransitionIdAfter = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.targetTransitionIdBefore = target.lastTransitionId;
        writeInput.targetTransitionIdAfter = restorationTransitionId;
        writeInput.authorityId = authorityId;
        writeInput.reasonHash = reasonHash;
        writeInput.reasonURI = reasonURI;
        writeInput.actor = authorityActor;
        transitionId = _recordTransition(challenge, writeInput);
        challenge.lastTransitionId = transitionId;
        _decrementOpenChallenge(challenge);
    }

    function closeChallenge(
        uint256 challengeId,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 reasonHash,
        string calldata reasonURI
    ) external nonReentrantLifecycle returns (uint256 transitionId) {
        ChallengeRecord storage challenge = _challengeStorage(challengeId);
        bool preResolutionClose = challenge.status == ChallengeStatus.ConcernFiled;
        bool postResolutionClose =
            challenge.status == ChallengeStatus.Resolved || challenge.status == ChallengeStatus.RestorationAvailable;
        if (
            (!preResolutionClose && !postResolutionClose)
                || (preResolutionClose && challenge.outcome != ChallengeOutcome.None) || reasonHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        address authorityActor =
            _requireNonConflictedAuthority(challenge, roleKey, AVACoreTypes.ACTION_CLOSE_CHALLENGE, authorityId);
        _validateStoredChallengePolicies(
            challenge,
            StoredPolicyInput({
                actionKey: AVACoreTypes.ACTION_CLOSE_CHALLENGE,
                roleKey: roleKey,
                authorityId: authorityId,
                outcome: challenge.outcome,
                reasonHash: reasonHash,
                authorityActor: authorityActor
            })
        );
        transitionId = _recordClosure(challenge, authorityId, reasonHash, reasonURI, authorityActor);
        _decrementOpenChallenge(challenge);
    }

    function correctionTargetVersion(uint256 challengeId) external view returns (uint256) {
        ChallengeRecord storage challenge = challenges[challengeId];
        if (challenge.status != ChallengeStatus.AdmissibilityScreening) revert AVACoreTypes.InvalidState(challengeId);
        return GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId).lastTransitionId;
    }

    function applyCorrectionReview(uint256 reviewId) external nonReentrantLifecycle {
        IAVACorrectionReview registry = IAVACorrectionReview(address(GOVERNANCE_KERNEL.CORRECTIONS()));
        if (msg.sender != address(registry)) {
            revert AVACoreTypes.InvalidState(reviewId);
        }
        IAVACorrectionReview.Disposition memory review = registry.activeDisposition(reviewId);
        ChallengeRecord storage challenge = challenges[review.originCaseId];
        // Core checked this exact pending case/head before entering this atomic callback.
        uint256 beforeId =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId).lastTransitionId;
        uint256 afterId = beforeId;
        ChallengeOutcome outcome;
        if (review.outcome == IAVACorrectionReview.Outcome.Withdrawn) {
            afterId = GOVERNANCE_KERNEL.applyAuthorisedCorrection(reviewId);
            outcome = ChallengeOutcome.Upheld;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Affirmed) {
            outcome = ChallengeOutcome.ReviewAffirmed;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Residual) {
            outcome = ChallengeOutcome.ReviewResidual;
        } else if (review.outcome == IAVACorrectionReview.Outcome.EvidenceUnavailable) {
            outcome = ChallengeOutcome.Unavailable;
        } else if (review.outcome == IAVACorrectionReview.Outcome.TargetChanged) {
            outcome = ChallengeOutcome.TargetChangedNoReversal;
        } else {
            revert AVACoreTypes.InvalidState(reviewId);
        }
        challenge.status = ChallengeStatus.Resolved;
        challenge.outcome = outcome;
        challenge.decisionEvidenceReceiptId = review.evidenceId;
        challenge.targetTransitionIdAfterResolution = afterId;
        uint256 challengeHead =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengeRecognisedStateId).lastTransitionId;
        challenge.challengeStateTransitionIdAfterResolution = challengeHead;
        _recordTransition(
            challenge,
            TransitionWriteInput(
                ChallengeTransitionKind.Resolution,
                ChallengeStatus.AdmissibilityScreening,
                ChallengeStatus.Resolved,
                outcome,
                challengeHead,
                challengeHead,
                beforeId,
                afterId,
                review.authorityId,
                review.reasonHash,
                "",
                review.actor
            )
        );
        // Independent disposition closes its own accepted case; a historical close-policy veto cannot strand it.
        _recordClosure(challenge, review.authorityId, review.reasonHash, "", review.actor);
        _decrementOpenChallenge(challenge);
    }

    function _registerCorrectionCase(ChallengeRecord storage challenge) private {
        IAVACorrectionReview.CaseInput memory input;
        input.kind = IAVACorrectionReview.TargetKind.Source;
        input.appId = challenge.appId;
        input.workflowKey = challenge.workflowKey;
        input.packageId = challenge.packageId;
        input.targetPackageId = challenge.targetPackageId;
        input.sourceStateId = challenge.challengedRecognisedStateId;
        input.originCaseId = challenge.id;
        input.targetId = challenge.challengedRecognisedStateId;
        input.originalTargetVersion = challenge.targetTransitionIdAtFiling;
        input.filingEvidenceId = challenge.evidenceReceiptId;
        input.challengerSubjectId = challenge.challengerSubjectId;
        input.challenger = challenge.filedBy;
        uint256 id = GOVERNANCE_KERNEL.CORRECTIONS().registerCase(input);
        correctionReviewCaseIdByChallenge[challenge.id] = id;
    }

    function getChallenge(uint256 id) external view returns (ChallengeRecord memory challenge) {
        challenge = challenges[id];
        if (challenge.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function getChallengeTransition(uint256 id) external view returns (ChallengeTransitionRecord memory transition) {
        transition = transitions[id];
        if (transition.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function validateTransition(
        uint256 packageId,
        uint256 recognisedStateId,
        AVACoreTypes.RecognisedStateStatus,
        AVACoreTypes.RecognisedStateStatus toStatus,
        AVACoreTypes.TransitionKind
    ) external view {
        AVAGovernanceKernel.RecognisedStateReference memory state =
            GOVERNANCE_KERNEL.getRecognisedStateReference(recognisedStateId);
        if (state.packageId != packageId) revert AVACoreTypes.InvalidState(recognisedStateId);
        if (
            toStatus == AVACoreTypes.RecognisedStateStatus.Vested
                && (openChallengeCountByRecognisedState[recognisedStateId] != 0
                    || decisionBoundChallengeState[recognisedStateId])
        ) {
            revert AVACoreTypes.InvalidState(recognisedStateId);
        }
    }

    function _validateChallengeFiling(ChallengeFilingInput calldata input)
        private
        view
        returns (
            AVAGovernanceKernel.RecognisedStateReference memory challengeState,
            AVAGovernanceKernel.GovernedObjectReference memory challengeObject,
            AVAGovernanceKernel.RecognisedStateReference memory target
        )
    {
        challengeState = GOVERNANCE_KERNEL.getRecognisedStateReference(input.challengeRecognisedStateId);
        target = GOVERNANCE_KERNEL.getRecognisedStateReference(input.challengedRecognisedStateId);
        challengeObject = GOVERNANCE_KERNEL.getGovernedObjectReference(challengeState.governedObjectId);
        if (
            challengeState.id == target.id || challengeState.appId != input.appId
                || challengeState.workflowKey != input.workflowKey || challengeState.packageId != input.packageId
                || challengeState.stage != AVACoreTypes.Stage.Verification
                || challengeState.status != AVACoreTypes.RecognisedStateStatus.Registered || target.appId != input.appId
                || !AVACoreTransitionRules.isChallengeTarget(target.status)
                || challengeObject.id == target.governedObjectId
                || challengeObject.parentObjectId != target.governedObjectId
                || challengeObject.appId != challengeState.appId
                || challengeObject.packageId != challengeState.packageId
                || challengeObject.subjectId != challengeState.subjectId
                || challengeObject.evidenceReceiptId != challengeState.evidenceReceiptId
                || challengeObject.disclosurePolicyId != challengeState.disclosurePolicyId
        ) revert AVACoreTypes.InvalidState(input.challengeRecognisedStateId);

        _requireAuthority(input.appId, input.roleKey, AVACoreTypes.ACTION_FILE_CHALLENGE, challengeState.subjectId);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory challengePackage =
            RULE_PACKAGE_REGISTRY.getVerifiedPackageContext(input.packageId);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory targetPackage =
            RULE_PACKAGE_REGISTRY.getVerifiedPackageContext(target.packageId);
        if (
            challengePackage.appId != input.appId || challengePackage.workflowKey != input.workflowKey
                || targetPackage.appId != input.appId
                || challengePackage.compatibilityKey != targetPackage.compatibilityKey
                || GOVERNANCE_KERNEL.sourceBoundTransitionRequesterByPackage(target.packageId) != address(this)
                || address(GOVERNANCE_KERNEL.transitionGuardByPackage(target.packageId)) != address(this)
                || GOVERNANCE_KERNEL.sourceBoundTransitionRequesterByPackage(challengeState.packageId) != address(this)
                || address(GOVERNANCE_KERNEL.transitionGuardByPackage(challengeState.packageId)) != address(this)
        ) revert AVACoreTypes.InvalidState(input.packageId);
        _requireChallengeEvidence(challengeState);
        _requireDifferentAccounts(challengeState.subjectId, target.subjectId);
        _validateFilingPolicies(input, challengeState, challengeObject, target);
    }

    function _requestChallengeFilingTransition(
        ChallengeRecord storage challenge,
        AVAGovernanceKernel.RecognisedStateReference memory challengeState,
        AVAGovernanceKernel.RecognisedStateReference memory target,
        ChallengeFilingInput calldata input
    ) private returns (uint256) {
        bytes32 decisionHash = keccak256(
            abi.encode(
                keccak256("ava.extension.challenge.filing-decision.v1"),
                challenge.id,
                challengeState.id,
                challengeState.lastTransitionId,
                target.id,
                target.lastTransitionId,
                challenge.packageId,
                target.packageId,
                input.reasonHash
            )
        );
        return GOVERNANCE_KERNEL.requestSourceBoundTransition(
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: challengeState.id,
                expectedTransitionId: challengeState.lastTransitionId,
                decisionPackageId: challenge.packageId,
                sourceRecordId: challenge.id,
                decisionEvidenceReceiptId: challengeState.evidenceReceiptId,
                disclosureTargetId: target.id,
                roleKey: input.roleKey,
                authorityId: challengeState.subjectId,
                actionKey: AVACoreTypes.ACTION_FILE_CHALLENGE,
                decisionHash: decisionHash,
                toStatus: AVACoreTypes.RecognisedStateStatus.Challengeable,
                kind: AVACoreTypes.TransitionKind.Generic,
                reasonHash: input.reasonHash,
                reasonURI: input.reasonURI
            })
        );
    }

    function _validateFilingPolicies(
        ChallengeFilingInput calldata input,
        AVAGovernanceKernel.RecognisedStateReference memory challengeState,
        AVAGovernanceKernel.GovernedObjectReference memory challengeObject,
        AVAGovernanceKernel.RecognisedStateReference memory target
    ) internal view {
        if (address(AVAChallengePolicyValidation).code.length == 0) {
            revert AVACoreTypes.InvalidState(input.challengeRecognisedStateId);
        }
        AVAChallengePolicyValidation.validateFiling(
            GOVERNANCE_KERNEL,
            POLICY_ROUTER,
            input.appId,
            input.workflowKey,
            input.packageId,
            input.roleKey,
            challengeState,
            challengeObject.objectTypeKey,
            target
        );
    }

    function _validateStoredChallengePolicies(ChallengeRecord storage challenge, StoredPolicyInput memory input)
        internal
        view
    {
        if (address(AVAChallengePolicyValidation).code.length == 0) revert AVACoreTypes.InvalidState(challenge.id);
        AVAChallengePolicyValidation.validateStored(
            GOVERNANCE_KERNEL, EVIDENCE_REGISTRY, POLICY_ROUTER, challenge, input
        );
    }

    function _decisionHash(
        uint256 challengeId,
        bytes32 actionKey,
        uint256 targetTransitionId,
        ChallengeOutcome outcome,
        bytes32 reasonHash,
        uint256 packageId,
        uint256 targetPackageId
    ) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                challengeId,
                actionKey,
                targetTransitionId,
                outcome,
                reasonHash,
                packageId,
                targetPackageId,
                challenges[challengeId].evidenceReceiptId,
                challenges[challengeId].decisionEvidenceReceiptId
            )
        );
    }

    function _filingUnavailable(ChallengeRecord storage challenge) private view returns (bool) {
        return !IDENTITY_REGISTRY.getSubjectContext(challenge.challengerSubjectId).active
            || !EVIDENCE_REGISTRY.isEvidenceAvailableForPackage(challenge.evidenceReceiptId, challenge.packageId);
    }

    function _requireDecisionEvidence(ChallengeRecord storage challenge, uint256 evidenceId) private view {
        (bytes32 appId, bytes32 workflowKey, uint256 packageId, bytes32 subjectId,) =
            EVIDENCE_REGISTRY.requireUsableCorrectionEvidenceReferenceForPackage(evidenceId, challenge.packageId);
        if (appId != challenge.appId || workflowKey != challenge.workflowKey || packageId != challenge.packageId) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
        IDENTITY_REGISTRY.requireActiveSubjectReference(subjectId, challenge.appId);
    }

    function _requireChallengeEvidence(AVAGovernanceKernel.RecognisedStateReference memory challengeState)
        internal
        view
    {
        (
            bytes32 evidenceAppId,
            bytes32 evidenceWorkflowKey,
            uint256 evidencePackageId,
            bytes32 evidenceSubjectId,
            uint256 evidenceDisclosurePolicyId
        ) = EVIDENCE_REGISTRY.requireUsableEvidenceReferenceForPackage(
            challengeState.evidenceReceiptId, challengeState.packageId
        );
        if (
            evidenceAppId != challengeState.appId || evidenceWorkflowKey != challengeState.workflowKey
                || evidencePackageId != challengeState.packageId || evidenceSubjectId != challengeState.subjectId
                || evidenceDisclosurePolicyId != challengeState.disclosurePolicyId
        ) {
            revert AVACoreTypes.InvalidState(challengeState.evidenceReceiptId);
        }
    }

    function _requireStoredChallengeEvidence(ChallengeRecord storage challenge) internal view {
        (
            bytes32 evidenceAppId,
            bytes32 evidenceWorkflowKey,
            uint256 evidencePackageId,
            bytes32 evidenceSubjectId,
            uint256 evidenceDisclosurePolicyId
        ) = EVIDENCE_REGISTRY.requireUsableEvidenceReferenceForPackage(challenge.evidenceReceiptId, challenge.packageId);
        if (
            evidenceAppId != challenge.appId || evidenceWorkflowKey != challenge.workflowKey
                || evidencePackageId != challenge.packageId || evidenceSubjectId != challenge.challengerSubjectId
                || evidenceDisclosurePolicyId != challenge.disclosurePolicyId
        ) {
            revert AVACoreTypes.InvalidState(challenge.evidenceReceiptId);
        }
    }

    function _requireNonConflictedAuthority(
        ChallengeRecord storage challenge,
        bytes32 roleKey,
        bytes32 actionKey,
        bytes32 authorityId
    ) internal view returns (address authorityActor) {
        _requireAuthority(challenge.appId, roleKey, actionKey, authorityId);
        AVAIdentityRegistry.SubjectContext memory authoritySubject = IDENTITY_REGISTRY.getSubjectContext(authorityId);
        AVAIdentityRegistry.SubjectContext memory challengerSubject =
            IDENTITY_REGISTRY.getSubjectContext(challenge.challengerSubjectId);
        AVAGovernanceKernel.RecognisedStateReference memory target =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId);
        AVAIdentityRegistry.SubjectContext memory targetSubject = IDENTITY_REGISTRY.getSubjectContext(target.subjectId);
        if (authoritySubject.account == challengerSubject.account || authoritySubject.account == targetSubject.account)
        {
            revert AVACoreTypes.NotAuthorised(msg.sender, actionKey);
        }
        authorityActor = authoritySubject.account;
    }

    function _requireAuthority(bytes32 appId, bytes32 roleKey, bytes32 actionKey, bytes32 authorityId) internal view {
        bytes32 callerAuthorityId =
            AUTHORITY_MATRIX.requireAuthorisedCanonicalSubject(msg.sender, appId, roleKey, actionKey);
        if (callerAuthorityId != authorityId) {
            revert AVACoreTypes.SubjectMismatch(callerAuthorityId, authorityId);
        }
    }

    function _requireDifferentAccounts(bytes32 firstSubjectId, bytes32 secondSubjectId) internal view {
        AVAIdentityRegistry.SubjectContext memory first = IDENTITY_REGISTRY.getSubjectContext(firstSubjectId);
        AVAIdentityRegistry.SubjectContext memory second = IDENTITY_REGISTRY.getSubjectContext(secondSubjectId);
        if (first.account == second.account) {
            revert AVACoreTypes.NotAuthorised(msg.sender, AVACoreTypes.ACTION_FILE_CHALLENGE);
        }
    }

    function _recordTransition(ChallengeRecord storage challenge, TransitionWriteInput memory input)
        internal
        returns (uint256 transitionId)
    {
        transitionId = nextTransitionId++;
        ChallengeTransitionRecord storage record = transitions[transitionId];
        record.id = transitionId;
        record.challengeId = challenge.id;
        record.appId = challenge.appId;
        record.packageId = challenge.packageId;
        record.targetPackageId = challenge.targetPackageId;
        record.challengeRecognisedStateId = challenge.challengeRecognisedStateId;
        record.challengedRecognisedStateId = challenge.challengedRecognisedStateId;
        record.kind = input.kind;
        record.fromStatus = input.fromStatus;
        record.toStatus = input.toStatus;
        record.outcome = input.outcome;
        record.challengeStateTransitionIdBefore = input.challengeStateTransitionIdBefore;
        record.challengeStateTransitionIdAfter = input.challengeStateTransitionIdAfter;
        record.targetTransitionIdBefore = input.targetTransitionIdBefore;
        record.targetTransitionIdAfter = input.targetTransitionIdAfter;
        record.evidenceReceiptId = challenge.evidenceReceiptId;
        record.authorityId = input.authorityId;
        record.reasonHash = input.reasonHash;
        record.reasonURI = input.reasonURI;
        record.createdBy = input.actor;
        record.createdAt = uint64(block.timestamp);
        record.decisionEvidenceReceiptId = challenge.decisionEvidenceReceiptId;
        emit ChallengeTransitionRecorded(
            transitionId,
            challenge.id,
            input.kind,
            input.fromStatus,
            input.toStatus,
            input.outcome,
            input.targetTransitionIdAfter,
            input.authorityId,
            input.actor
        );
    }

    function _recordClosure(
        ChallengeRecord storage challenge,
        bytes32 authorityId,
        bytes32 reasonHash,
        string memory reasonURI,
        address authorityActor
    ) internal returns (uint256 transitionId) {
        uint256 targetTransitionId =
            GOVERNANCE_KERNEL.getRecognisedStateReference(challenge.challengedRecognisedStateId).lastTransitionId;
        ChallengeStatus fromStatus = challenge.status;
        challenge.status = ChallengeStatus.Closed;
        TransitionWriteInput memory writeInput;
        writeInput.kind = ChallengeTransitionKind.Closure;
        writeInput.fromStatus = fromStatus;
        writeInput.toStatus = challenge.status;
        writeInput.outcome = challenge.outcome;
        writeInput.challengeStateTransitionIdBefore = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.challengeStateTransitionIdAfter = challenge.challengeStateTransitionIdAfterResolution;
        writeInput.targetTransitionIdBefore = targetTransitionId;
        writeInput.targetTransitionIdAfter = targetTransitionId;
        writeInput.authorityId = authorityId;
        writeInput.reasonHash = reasonHash;
        writeInput.reasonURI = reasonURI;
        writeInput.actor = authorityActor;
        transitionId = _recordTransition(challenge, writeInput);
        challenge.lastTransitionId = transitionId;
    }

    function _requestRestorationTransition(
        ChallengeRecord storage challenge,
        AVAGovernanceKernel.RecognisedStateReference memory target,
        bytes32 roleKey,
        bytes32 authorityId,
        AVACoreTypes.RecognisedStateStatus restorationStatus,
        bytes32 reasonHash,
        string calldata reasonURI
    ) private returns (uint256) {
        bytes32 decisionHash = _restorationDecisionHash(challenge, target.lastTransitionId, reasonHash);
        return GOVERNANCE_KERNEL.requestSourceBoundTransition(
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: challenge.challengedRecognisedStateId,
                expectedTransitionId: target.lastTransitionId,
                decisionPackageId: challenge.packageId,
                sourceRecordId: challenge.id,
                decisionEvidenceReceiptId: challenge.decisionEvidenceReceiptId,
                disclosureTargetId: challenge.challengedRecognisedStateId,
                roleKey: roleKey,
                authorityId: authorityId,
                actionKey: AVACoreTypes.ACTION_APPLY_RESTORATION,
                decisionHash: decisionHash,
                toStatus: restorationStatus,
                kind: AVACoreTypes.TransitionKind.Restoration,
                reasonHash: reasonHash,
                reasonURI: reasonURI
            })
        );
    }

    function _restorationDecisionHash(ChallengeRecord storage challenge, uint256 targetTransitionId, bytes32 reasonHash)
        private
        view
        returns (bytes32)
    {
        return _decisionHash(
            challenge.id,
            AVACoreTypes.ACTION_APPLY_RESTORATION,
            targetTransitionId,
            challenge.outcome,
            reasonHash,
            challenge.packageId,
            challenge.targetPackageId
        );
    }

    function _decrementOpenChallenge(ChallengeRecord storage challenge) internal {
        uint256 openCount = openChallengeCountByRecognisedState[challenge.challengedRecognisedStateId];
        if (openCount == 0) revert AVACoreTypes.InvalidState(challenge.id);
        openChallengeCountByRecognisedState[challenge.challengedRecognisedStateId] = openCount - 1;
    }

    function _challengeStorage(uint256 id) internal view returns (ChallengeRecord storage challenge) {
        challenge = challenges[id];
        if (challenge.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _isRestorableOutcome(ChallengeOutcome outcome) private pure returns (bool) {
        return outcome == ChallengeOutcome.Upheld || outcome == ChallengeOutcome.RejectedGoodFaith
            || outcome == ChallengeOutcome.MaliciousOrFabricated;
    }

    function _restorationStatus(AVACoreTypes.RecognisedStateStatus targetStatusAtFiling)
        private
        pure
        returns (AVACoreTypes.RecognisedStateStatus)
    {
        if (targetStatusAtFiling == AVACoreTypes.RecognisedStateStatus.Challengeable) {
            return AVACoreTypes.RecognisedStateStatus.Challengeable;
        }
        if (
            targetStatusAtFiling == AVACoreTypes.RecognisedStateStatus.Vested
                || targetStatusAtFiling == AVACoreTypes.RecognisedStateStatus.Restored
        ) {
            return AVACoreTypes.RecognisedStateStatus.Restored;
        }
        revert AVACoreTypes.InvalidState(uint256(targetStatusAtFiling));
    }

    function _requireRestorationLineage(
        ChallengeRecord storage challenge,
        AVAGovernanceKernel.RecognisedStateReference memory target
    ) private view {
        if (challenge.outcome == ChallengeOutcome.Upheld) {
            if (
                target.status != AVACoreTypes.RecognisedStateStatus.Downgraded
                    && target.status != AVACoreTypes.RecognisedStateStatus.Voided
            ) {
                revert AVACoreTypes.InvalidState(challenge.id);
            }
            return;
        }
        if (
            target.lastTransitionId != challenge.targetTransitionIdAtFiling
                || challenge.targetTransitionIdAfterResolution != challenge.targetTransitionIdAtFiling
                || target.status != challenge.targetStatusAtFiling
        ) {
            revert AVACoreTypes.InvalidState(challenge.id);
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(
            abi.encode(
                address(GOVERNANCE_KERNEL),
                address(AUTHORITY_MATRIX),
                address(IDENTITY_REGISTRY),
                address(RULE_PACKAGE_REGISTRY),
                address(EVIDENCE_REGISTRY)
            )
        );
    }

    function _filingKey(bytes32 appId, uint256 recognisedStateId, uint256 transitionId, address challengerAccount)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(appId, recognisedStateId, transitionId, challengerAccount));
    }
}
