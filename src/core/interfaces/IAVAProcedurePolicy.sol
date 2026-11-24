// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {IRuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice Review of a procedural downstream decision; it does not form a recognised state.
interface IAVAProcedurePolicy is IRuleModuleIdentity {
    enum Outcome {
        None,
        Affirmed,
        Withdrawn,
        Replaced,
        EvidenceUnavailable,
        TargetChanged,
        ReviewedResidual
    }

    struct Review {
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        uint256 requestId;
        uint256 decisionId;
        uint256 challengeId;
        uint256 currentDecisionId;
        address originalActor;
        address challenger;
        address resolver;
        bytes32 roleKey;
        bytes32 authorityId;
        uint256 decisionEvidenceId;
        Outcome outcome;
        bytes32 replacementKey;
        bytes32 reasonHash;
        uint64 evaluatedAt;
    }
    function validateProcedureReview(Review calldata review) external view;
}
