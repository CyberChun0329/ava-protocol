// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice The Core's separately authorised review of an accepted unresolved case.
/// Ordinary domain policy cannot veto this retained correction path.
interface IAVACorrectionReview {
    enum TargetKind {
        Source,
        Allocation,
        Effect,
        Procedure
    }
    enum Outcome {
        None,
        Affirmed,
        Withdrawn,
        Residual,
        Compensate,
        EvidenceUnavailable,
        TargetChanged
    }

    struct CaseInput {
        TargetKind kind;
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        uint256 targetPackageId;
        uint256 sourceStateId;
        uint256 originCaseId;
        uint256 targetId;
        uint256 originalTargetVersion;
        uint256 filingEvidenceId;
        bytes32 challengerSubjectId;
        address originalActor;
        address challenger;
        address affectedActor;
    }

    struct CaseRecord {
        uint256 id;
        address origin;
        CaseInput input;
        uint64 acceptedAt;
        uint256 reviewId;
    }

    struct ReviewInput {
        uint256 caseId;
        uint256 expectedTargetVersion;
        Outcome outcome;
        uint256 evidenceId;
        bytes32 roleKey;
        bytes32 authorityId;
        bytes32 reasonHash;
        address asset;
        address recipient;
        uint256 amount;
        FindingInput finding;
    }

    /// @notice A claim accepted by the adjudicator, distinct from the selected disposition or remedy.
    /// Hashes commit the bounded claim, permitted use and evidential burden in the case material.
    /// Attribution and substantive Verification may be recorded atomically by the adjudication.
    struct FindingInput {
        uint256 existingFindingId;
        uint256 supersedesFindingId;
        bytes32 claimHash;
        bytes32 useScopeHash;
        bytes32 burdenHash;
    }

    /// @notice A recognised conclusion in the correction-case family, not a business-state replacement.
    /// Its case fixes app, workflow, historical package, target and accepted filing provenance.
    struct RecognisedFinding {
        uint256 id;
        uint256 caseId;
        uint256 targetVersion;
        bytes32 claimHash;
        bytes32 useScopeHash;
        bytes32 burdenHash;
        uint256 evidenceId;
        bytes32 verifierAuthorityId;
        address verifier;
        bytes32 formationAction;
        uint256 supersedesFindingId;
        bool independentReview;
        uint64 formedAt;
    }

    struct FindingFormation {
        uint256 caseId;
        uint256 targetVersion;
        uint256 evidenceId;
        bytes32 roleKey;
        bytes32 authorityId;
        address verifier;
        bool substantive;
        FindingInput finding;
    }

    struct ReviewRecord {
        uint256 id;
        ReviewInput input;
        address actor;
        uint64 reviewedAt;
        bytes32 reviewHash;
    }

    struct SourceRepair {
        uint256 stateId;
        uint256 expectedTransitionId;
        uint256 decisionPackageId;
        uint256 evidenceId;
        bytes32 authorityId;
        address actor;
        bytes32 reasonHash;
    }

    struct Disposition {
        uint256 caseId;
        uint256 originCaseId;
        uint256 expectedTargetVersion;
        Outcome outcome;
        uint256 evidenceId;
        bytes32 authorityId;
        address actor;
        bytes32 reasonHash;
    }

    struct ReviewTerms {
        uint256 originCaseId;
        uint256 expectedTargetVersion;
        Outcome outcome;
        uint256 evidenceId;
        bytes32 roleKey;
        bytes32 authorityId;
        address actor;
        bytes32 reasonHash;
        address asset;
        address recipient;
        uint256 amount;
        bytes32 reviewHash;
    }

    function registerCase(CaseInput calldata input) external returns (uint256);
    function bindRequestOrigin(bytes32 appId, address origin) external;
    function requestOriginCodeHash(bytes32 appId, address origin) external view returns (bytes32);
    function requestOriginDisabled(bytes32 appId, address origin) external view returns (bool);
    function setRequestOriginEnabled(bytes32 appId, address origin, bool enabled) external;
    function review(ReviewInput calldata input) external returns (uint256);
    function recordFinding(FindingFormation calldata input) external returns (uint256);
    function findingIdByCase(uint256 caseId) external view returns (uint256);
    function getFinding(uint256 id) external view returns (RecognisedFinding memory);
    function requireUsableFindingReference(uint256 id) external view returns (RecognisedFinding memory);
    function supersededByFindingId(uint256 id) external view returns (uint256);
    function getCase(uint256 id) external view returns (CaseRecord memory);
    function getReview(uint256 id) external view returns (ReviewRecord memory);
    function requireActiveProcedureWithdrawal(
        uint256 reviewId,
        address origin,
        uint256 decisionId,
        bytes32 appId,
        bytes32 workflowKey,
        uint256 packageId
    ) external view;
    function activeReviewId() external view returns (uint256);
    function activeDisposition(uint256 reviewId) external view returns (Disposition memory);
    function activeReviewTerms(uint256 reviewId) external view returns (ReviewTerms memory);
    function canRegisterEvidence(uint256 caseId, address actor, bytes32 roleKey, bytes32 authorityId)
        external
        view
        returns (bytes32 appId, bytes32 workflowKey, uint256 packageId);
    function sourceRepair(uint256 reviewId, address origin) external view returns (SourceRepair memory);
}

interface IAVACorrectionReviewOrigin {
    function GOVERNANCE_KERNEL() external view returns (address);
    function correctionTargetVersion(uint256 originCaseId) external view returns (uint256);
    function applyCorrectionReview(uint256 reviewId) external;
}

/// @notice Procedural disposition can retire a target while retaining its decision head.
interface IAVAProcedureCorrectionReviewOrigin {
    function correctionTargetCurrent(uint256 originCaseId) external view returns (bool);
}
