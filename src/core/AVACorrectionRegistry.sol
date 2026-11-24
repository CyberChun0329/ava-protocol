// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "./AVACoreTypes.sol";
import {AVACapabilityKeys} from "./AVACapabilityKeys.sol";
import {AVAGovernanceKernel} from "./AVAGovernanceKernel.sol";
import {AVACoreRulePackageRegistry} from "./AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "./AVAEvidenceRegistry.sol";
import {
    IAVACorrectionReview,
    IAVACorrectionReviewOrigin,
    IAVAProcedureCorrectionReviewOrigin
} from "./interfaces/IAVACorrectionReview.sol";

/// @notice A retained, separately authorised review path for accepted cases.
/// @dev This is an explicit Core rule, installed with the host, not an administrator override.
/// Domain policy remains historical evidence; it cannot veto this independent review.
contract AVACorrectionRegistry is IAVACorrectionReview {
    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    mapping(uint256 => CaseRecord) private cases;
    mapping(uint256 => ReviewRecord) private reviews;
    mapping(bytes32 => uint256) public caseIdByOrigin;
    uint256 public nextCaseId = 1;
    uint256 public nextReviewId = 1;
    uint256 public activeReviewId;
    mapping(uint256 => RecognisedFinding) private findings;
    mapping(uint256 => uint256) public findingIdByCase;
    mapping(uint256 => uint256) public supersededByFindingId;
    uint256 public nextFindingId = 1;
    mapping(bytes32 => mapping(address => bytes32)) public requestOriginCodeHash;
    mapping(bytes32 => mapping(address => bool)) public requestOriginDisabled;

    event CaseAccepted(uint256 indexed caseId, address indexed origin, uint256 indexed originCaseId, TargetKind kind);
    event CaseReviewed(uint256 indexed reviewId, uint256 indexed caseId, Outcome outcome, address actor);
    event FindingRecognised(uint256 indexed findingId, uint256 indexed caseId, bytes32 claimHash, bytes32 useScopeHash);
    event FindingReferenced(uint256 indexed findingId, uint256 indexed caseId);
    event RequestOriginBound(bytes32 indexed appId, address indexed origin, bytes32 codeHash);
    event RequestOriginEnabled(bytes32 indexed appId, address indexed origin, bool enabled);

    constructor(AVAGovernanceKernel host) {
        GOVERNANCE_KERNEL = host;
    }

    /// @notice Installs the trusted actor relay for this app's ordinary request adjudication.
    /// It is an immutable code binding, not a grant of any person's resolution/review powers.
    function bindRequestOrigin(bytes32 appId, address origin) external {
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX().APPLICATION_REGISTRY().requireApplicationAdmin(msg.sender, appId);
        if (
            origin.code.length == 0
                || IAVACorrectionReviewOrigin(origin).GOVERNANCE_KERNEL() != address(GOVERNANCE_KERNEL)
        ) {
            revert AVACoreTypes.InvalidState(0);
        }
        bytes32 pinned = requestOriginCodeHash[appId][origin];
        if (pinned != bytes32(0) && pinned != origin.codehash) revert AVACoreTypes.InvalidState(0);
        requestOriginCodeHash[appId][origin] = origin.codehash;
        emit RequestOriginBound(appId, origin, origin.codehash);
    }

    /// @notice Changes future request intake and ordinary findings, retaining accepted Core review and history.
    function setRequestOriginEnabled(bytes32 appId, address origin, bool enabled) external {
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX().APPLICATION_REGISTRY().requireApplicationAdmin(msg.sender, appId);
        bytes32 pinned = requestOriginCodeHash[appId][origin];
        if (pinned == bytes32(0)) revert AVACoreTypes.InvalidState(0);
        if (
            enabled
                && (origin.code.length == 0
                    || pinned != origin.codehash
                    || IAVACorrectionReviewOrigin(origin).GOVERNANCE_KERNEL() != address(GOVERNANCE_KERNEL))
        ) revert AVACoreTypes.InvalidState(0);
        requestOriginDisabled[appId][origin] = !enabled;
        emit RequestOriginEnabled(appId, origin, enabled);
    }

    /// @notice Records the accepted claim after the origin's substantive adjudication checks.
    /// The declared origin rule assigns its resolution authority both Verification and disposition roles.
    /// A finding is reusable within its exact target/use/burden, and never authorises a remedy by itself.
    function recordFinding(FindingFormation calldata input) external returns (uint256) {
        // Unscreened procedural exits may have no accepted review case yet.
        if (!input.substantive) {
            _requireEmptyFinding(input.finding, input.caseId);
            return 0;
        }
        CaseRecord storage item = _case(input.caseId);
        if (msg.sender != item.origin || activeReviewId != 0 || input.targetVersion != _requirePending(item)) {
            revert AVACoreTypes.InvalidState(input.caseId);
        }
        if (item.input.kind == TargetKind.Allocation || item.input.kind == TargetKind.Effect) {
            bytes32 pinned = requestOriginCodeHash[item.input.appId][msg.sender];
            if (
                requestOriginDisabled[item.input.appId][msg.sender] || pinned == bytes32(0)
                    || pinned != msg.sender.codehash
            ) {
                revert AVACoreTypes.NotAuthorised(msg.sender, _formationAction(item.input.kind));
            }
        }
        return _recordFinding(item, input, false);
    }

    function getFinding(uint256 id) external view returns (RecognisedFinding memory) {
        if (findings[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return findings[id];
    }

    /// @notice Current reuse eligibility under the same evidence rules as an existing finding reference.
    function requireUsableFindingReference(uint256 id) external view returns (RecognisedFinding memory) {
        RecognisedFinding storage finding = findings[id];
        if (finding.id == 0) revert AVACoreTypes.UnknownReference(id);
        if (supersededByFindingId[id] != 0) revert AVACoreTypes.InvalidState(id);
        _requireFindingEvidence(
            cases[finding.caseId], finding.evidenceId, finding.verifierAuthorityId, finding.independentReview
        );
        return finding;
    }

    function _recordFinding(CaseRecord storage item, FindingFormation memory input, bool independent)
        private
        returns (uint256 id)
    {
        FindingInput memory accepted = input.finding;
        if (!input.substantive) {
            _requireEmptyFinding(accepted, item.id);
            return 0;
        }
        if (
            findingIdByCase[item.id] != 0 || accepted.claimHash == bytes32(0) || accepted.useScopeHash == bytes32(0)
                || accepted.burdenHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(item.id);
        }
        bytes32 action = independent ? AVACoreTypes.ACTION_REVIEW_CORRECTION : _formationAction(item.input.kind);
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(input.verifier, item.input.appId, input.roleKey, action, input.authorityId);
        _requireFindingEvidence(item, input.evidenceId, input.authorityId, independent);
        if (accepted.existingFindingId != 0) {
            id = accepted.existingFindingId;
            RecognisedFinding storage prior = findings[id];
            _requireSameFindingTarget(item, prior);
            if (
                accepted.supersedesFindingId != 0 || supersededByFindingId[id] != 0
                    || accepted.claimHash != prior.claimHash || accepted.useScopeHash != prior.useScopeHash
                    || accepted.burdenHash != prior.burdenHash
            ) revert AVACoreTypes.InvalidState(id);
            _requireFindingEvidence(
                cases[prior.caseId], prior.evidenceId, prior.verifierAuthorityId, prior.independentReview
            );
        } else {
            uint256 previous = accepted.supersedesFindingId;
            if (previous != 0) {
                _requireSameFindingTarget(item, findings[previous]);
                if (supersededByFindingId[previous] != 0 || findings[previous].useScopeHash != accepted.useScopeHash) {
                    revert AVACoreTypes.InvalidState(previous);
                }
            }
            id = nextFindingId++;
            findings[id] = RecognisedFinding(
                id,
                item.id,
                input.targetVersion,
                accepted.claimHash,
                accepted.useScopeHash,
                accepted.burdenHash,
                input.evidenceId,
                input.authorityId,
                input.verifier,
                action,
                previous,
                independent,
                uint64(block.timestamp)
            );
            if (previous != 0) supersededByFindingId[previous] = id;
            emit FindingRecognised(id, item.id, accepted.claimHash, accepted.useScopeHash);
        }
        findingIdByCase[item.id] = id;
        emit FindingReferenced(id, item.id);
    }

    function _requireEmptyFinding(FindingInput memory input, uint256 caseId) private pure {
        if (
            input.existingFindingId != 0 || input.supersedesFindingId != 0 || input.claimHash != bytes32(0)
                || input.useScopeHash != bytes32(0) || input.burdenHash != bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(caseId);
        }
    }

    function _requireSameFindingTarget(CaseRecord storage item, RecognisedFinding storage prior) private view {
        CaseRecord storage original = cases[prior.caseId];
        if (
            prior.id == 0 || item.origin != original.origin || item.input.appId != original.input.appId
                || item.input.workflowKey != original.input.workflowKey
                || item.input.packageId != original.input.packageId || item.input.kind != original.input.kind
                || item.input.targetId != original.input.targetId
                || item.input.sourceStateId != original.input.sourceStateId
        ) revert AVACoreTypes.InvalidState(prior.id);
    }

    function _requireFindingEvidence(CaseRecord storage item, uint256 id, bytes32 authorityId, bool independent)
        private
        view
    {
        if (independent) {
            _requireEvidence(item, id, authorityId);
        } else {
            (bytes32 evidenceAppId, bytes32 evidenceWorkflowKey,, bytes32 evidenceSubjectId,) = GOVERNANCE_KERNEL.EVIDENCE_REGISTRY()
                .requireUsableCorrectionEvidenceReferenceForPackage(id, item.input.packageId);
            if (evidenceAppId != item.input.appId || evidenceWorkflowKey != item.input.workflowKey) {
                revert AVACoreTypes.InvalidState(id);
            }
            GOVERNANCE_KERNEL.IDENTITY_REGISTRY().requireActiveSubjectReference(evidenceSubjectId, evidenceAppId);
        }
    }

    function _formationAction(TargetKind kind) private pure returns (bytes32) {
        if (kind == TargetKind.Source) return AVACoreTypes.ACTION_RESOLVE_CHALLENGE;
        if (kind == TargetKind.Procedure) return keccak256("ava.extension.procedure.challenge.resolve.v1");
        return keccak256("ava.extension.request.challenge.resolve.v1");
    }

    function registerCase(CaseInput calldata input) external returns (uint256 id) {
        CaseInput memory accepted = input;
        if (
            activeReviewId != 0 || input.originCaseId == 0 || input.targetId == 0 || input.filingEvidenceId == 0
                || input.challenger == address(0) || input.challengerSubjectId == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(input.originCaseId);
        }
        if (IAVACorrectionReviewOrigin(msg.sender).GOVERNANCE_KERNEL() != address(GOVERNANCE_KERNEL)) {
            revert AVACoreTypes.InvalidState(input.originCaseId);
        }
        AVACoreRulePackageRegistry.RulePackage memory rule =
            GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getRulePackageById(input.packageId);
        if (rule.appId != input.appId || rule.workflowKey != input.workflowKey) {
            revert AVACoreTypes.InvalidState(input.packageId);
        }
        if (input.kind == TargetKind.Source) {
            AVAGovernanceKernel.RecognisedStateReference memory state =
                GOVERNANCE_KERNEL.getRecognisedStateReference(input.targetId);
            if (
                GOVERNANCE_KERNEL.sourceBoundTransitionRequesterByPackage(state.packageId) != msg.sender
                    || state.packageId != input.targetPackageId || state.appId != input.appId
                    || state.id != input.sourceStateId
            ) revert AVACoreTypes.InvalidState(input.targetId);
            AVACoreTypes.RecognisedStateTransitionRecord memory occurrence =
                GOVERNANCE_KERNEL.getRecognisedStateTransition(input.originalTargetVersion);
            if (occurrence.recognisedStateId != state.id) {
                revert AVACoreTypes.InvalidState(input.originalTargetVersion);
            }
            accepted.originalActor = occurrence.createdBy;
            accepted.affectedActor = GOVERNANCE_KERNEL.IDENTITY_REGISTRY().getSubjectContext(state.subjectId).account;
        } else if (input.kind == TargetKind.Procedure) {
            bytes32[] memory keys = new bytes32[](1);
            keys[0] = AVACapabilityKeys.PROCEDURE_REVIEW;
            (, address[] memory modules) =
                GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getVerifiedModulesCompact(input.packageId, keys);
            if (modules[0] != msg.sender) revert AVACoreTypes.InvalidState(input.packageId);
        } else {
            bytes32 pinned = requestOriginCodeHash[input.appId][msg.sender];
            if (requestOriginDisabled[input.appId][msg.sender] || pinned == bytes32(0) || pinned != msg.sender.codehash)
            {
                revert AVACoreTypes.InvalidState(input.originCaseId);
            }
        }
        bytes32 key = keccak256(abi.encode(msg.sender, input.kind, input.originCaseId));
        if (caseIdByOrigin[key] != 0) revert AVACoreTypes.InvalidState(caseIdByOrigin[key]);
        id = nextCaseId++;
        cases[id] = CaseRecord(id, msg.sender, accepted, uint64(block.timestamp), 0);
        caseIdByOrigin[key] = id;
        emit CaseAccepted(id, msg.sender, input.originCaseId, input.kind);
    }

    function canRegisterEvidence(uint256 id, address actor, bytes32 roleKey, bytes32 authorityId)
        external
        view
        returns (bytes32, bytes32, uint256)
    {
        CaseRecord storage item = _case(id);
        _requirePending(item);
        _requireReviewer(item, actor, roleKey, authorityId);
        return (item.input.appId, item.input.workflowKey, item.input.packageId);
    }

    function review(ReviewInput calldata input) external returns (uint256 id) {
        if (activeReviewId != 0) revert AVACoreTypes.InvalidState(input.caseId);
        CaseRecord storage item = _case(input.caseId);
        uint256 targetVersion = _requirePending(item);
        _requireReviewer(item, msg.sender, input.roleKey, input.authorityId);
        if (
            input.reasonHash == bytes32(0) || input.outcome == Outcome.None || input.expectedTargetVersion != targetVersion
        ) {
            revert AVACoreTypes.InvalidState(item.id);
        }
        if (input.outcome == Outcome.TargetChanged) {
            // Withdrawal retains the procedural head but retires its pending control.
            if (
                input.evidenceId != 0
                    || (targetVersion == item.input.originalTargetVersion
                        && (item.input.kind != TargetKind.Procedure
                            || IAVAProcedureCorrectionReviewOrigin(item.origin)
                                .correctionTargetCurrent(item.input.originCaseId)))
            ) {
                revert AVACoreTypes.InvalidState(item.id);
            }
        } else if (input.outcome == Outcome.EvidenceUnavailable) {
            AVAEvidenceRegistry.EvidenceReference memory evidence =
                GOVERNANCE_KERNEL.EVIDENCE_REGISTRY().getEvidenceReference(item.input.filingEvidenceId);
            if (
                input.evidenceId != 0
                    || (evidence.status == AVACoreTypes.EvidenceStatus.Active
                        && GOVERNANCE_KERNEL.IDENTITY_REGISTRY().getSubjectContext(item.input.challengerSubjectId).active
                        && GOVERNANCE_KERNEL.EVIDENCE_REGISTRY()
                            .isEvidenceAvailableForPackage(item.input.filingEvidenceId, item.input.packageId))
            ) {
                revert AVACoreTypes.InvalidState(item.id);
            }
        } else {
            _requireEvidence(item, input.evidenceId, input.authorityId);
            if (
                (input.outcome == Outcome.Withdrawn || input.outcome == Outcome.Affirmed)
                    && targetVersion != item.input.originalTargetVersion
            ) revert AVACoreTypes.InvalidState(item.id);
        }
        if (input.outcome == Outcome.Withdrawn && item.input.kind == TargetKind.Effect) {
            revert AVACoreTypes.InvalidState(item.id);
        }
        if (input.outcome == Outcome.Compensate) {
            if (
                item.input.kind != TargetKind.Effect || input.asset.code.length == 0 || input.recipient == address(0)
                    || input.amount == 0
            ) revert AVACoreTypes.InvalidState(item.id);
            GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
                .requireAuthorisedSubject(
                    msg.sender,
                    item.input.appId,
                    input.roleKey,
                    keccak256("ava.extension.request.remedy.authorise.v1"),
                    input.authorityId
                );
        } else if (input.asset != address(0) || input.recipient != address(0) || input.amount != 0) {
            revert AVACoreTypes.InvalidState(item.id);
        }
        // Neutral outcomes close the case without accepting a merits finding.
        _recordFinding(
            item,
            FindingFormation({
                caseId: item.id,
                targetVersion: targetVersion,
                evidenceId: input.evidenceId,
                roleKey: input.roleKey,
                authorityId: input.authorityId,
                verifier: msg.sender,
                substantive: input.outcome != Outcome.EvidenceUnavailable && input.outcome != Outcome.TargetChanged,
                finding: input.finding
            }),
            true
        );
        id = nextReviewId++;
        bytes32 reviewHash = keccak256(abi.encode(block.chainid, address(this), id, input, msg.sender));
        reviews[id] = ReviewRecord(id, input, msg.sender, uint64(block.timestamp), reviewHash);
        item.reviewId = id;
        activeReviewId = id;
        IAVACorrectionReviewOrigin(item.origin).applyCorrectionReview(id);
        activeReviewId = 0;
        emit CaseReviewed(id, item.id, input.outcome, msg.sender);
    }

    function sourceRepair(uint256 id, address origin) external view returns (SourceRepair memory repair) {
        ReviewRecord storage record = reviews[id];
        CaseRecord storage item = cases[record.input.caseId];
        if (
            msg.sender != address(GOVERNANCE_KERNEL) || id == 0 || activeReviewId != id || item.origin != origin
                || item.reviewId != id || item.input.kind != TargetKind.Source
                || record.input.outcome != Outcome.Withdrawn
        ) revert AVACoreTypes.InvalidState(id);
        repair = SourceRepair(
            item.input.targetId,
            record.input.expectedTargetVersion,
            item.input.packageId,
            record.input.evidenceId,
            record.input.authorityId,
            record.actor,
            record.input.reasonHash
        );
    }

    function activeDisposition(uint256 id) external view returns (Disposition memory) {
        ReviewRecord storage record = reviews[id];
        if (id == 0 || activeReviewId != id || cases[record.input.caseId].origin != msg.sender) {
            revert AVACoreTypes.InvalidState(id);
        }
        return Disposition(
            record.input.caseId,
            cases[record.input.caseId].input.originCaseId,
            record.input.expectedTargetVersion,
            record.input.outcome,
            record.input.evidenceId,
            record.input.authorityId,
            record.actor,
            record.input.reasonHash
        );
    }

    /// @notice Checks the retained Core proof without making the caller decode full audit records.
    /// The target registry still checks its current decision head and applies its own local effects.
    function requireActiveProcedureWithdrawal(
        uint256 reviewId,
        address origin,
        uint256 decisionId,
        bytes32 appId,
        bytes32 workflowKey,
        uint256 packageId
    ) external view {
        ReviewRecord storage record = reviews[reviewId];
        CaseRecord storage item = cases[record.input.caseId];
        if (
            reviewId == 0 || activeReviewId != reviewId || item.origin != origin || item.reviewId != reviewId
                || item.input.kind != TargetKind.Procedure || item.input.targetId != decisionId
                || record.input.outcome != Outcome.Withdrawn || record.input.expectedTargetVersion != decisionId
                || item.input.appId != appId || item.input.workflowKey != workflowKey
                || item.input.targetPackageId != packageId
        ) revert AVACoreTypes.InvalidState(decisionId);
    }

    function activeReviewTerms(uint256 id) external view returns (ReviewTerms memory) {
        ReviewRecord storage record = reviews[id];
        CaseRecord storage item = cases[record.input.caseId];
        if (id == 0 || activeReviewId != id || item.origin != msg.sender) revert AVACoreTypes.InvalidState(id);
        return ReviewTerms(
            item.input.originCaseId,
            record.input.expectedTargetVersion,
            record.input.outcome,
            record.input.evidenceId,
            record.input.roleKey,
            record.input.authorityId,
            record.actor,
            record.input.reasonHash,
            record.input.asset,
            record.input.recipient,
            record.input.amount,
            record.reviewHash
        );
    }

    function getCase(uint256 id) external view returns (CaseRecord memory) {
        return _case(id);
    }

    function getReview(uint256 id) external view returns (ReviewRecord memory) {
        if (reviews[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return reviews[id];
    }

    function _case(uint256 id) private view returns (CaseRecord storage item) {
        item = cases[id];
        if (item.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _requirePending(CaseRecord storage item) private view returns (uint256) {
        if (item.reviewId != 0) revert AVACoreTypes.InvalidState(item.id);
        // The originating record checks that ordinary adjudication has not already won the race.
        return IAVACorrectionReviewOrigin(item.origin).correctionTargetVersion(item.input.originCaseId);
    }

    function _requireReviewer(CaseRecord storage item, address actor, bytes32 roleKey, bytes32 authorityId)
        private
        view
    {
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                actor, item.input.appId, roleKey, AVACoreTypes.ACTION_REVIEW_CORRECTION, authorityId
            );
        if (actor == item.input.originalActor || actor == item.input.challenger || actor == item.input.affectedActor) {
            revert AVACoreTypes.NotAuthorised(actor, AVACoreTypes.ACTION_REVIEW_CORRECTION);
        }
    }

    function _requireEvidence(CaseRecord storage item, uint256 id, bytes32 authorityId) private view {
        AVAEvidenceRegistry registry = GOVERNANCE_KERNEL.EVIDENCE_REGISTRY();
        AVAEvidenceRegistry.EvidenceReference memory evidence = registry.getEvidenceReference(id);
        if (
            registry.reviewEvidenceRegistryById(id) != address(this) || registry.reviewEvidenceCaseIdById(id) != item.id
                || evidence.status != AVACoreTypes.EvidenceStatus.Active || evidence.subjectId != authorityId
                || evidence.appId != item.input.appId || evidence.workflowKey != item.input.workflowKey
                || evidence.packageId != item.input.packageId
        ) revert AVACoreTypes.InvalidState(id);
        GOVERNANCE_KERNEL.IDENTITY_REGISTRY().requireActiveSubjectReference(evidence.subjectId, evidence.appId);
        GOVERNANCE_KERNEL.DISCLOSURE_REGISTRY()
            .requireActivePolicyReference(evidence.disclosurePolicyId, evidence.appId);
    }
}
