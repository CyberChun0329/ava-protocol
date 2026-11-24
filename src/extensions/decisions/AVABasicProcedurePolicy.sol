// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {IAVAProcedurePolicy} from "../../core/interfaces/IAVAProcedurePolicy.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";

/// @notice Explicit local rule: current independent review, including neutral evidence-loss handling.
contract AVABasicProcedurePolicy is IAVAProcedurePolicy, RuleModuleIdentity {
    bytes32 public immutable APP_ID;
    bytes32 public immutable WORKFLOW_KEY;
    bool public immutable INDEPENDENT_REVIEW;

    constructor(bytes32 appId, bytes32 workflowKey, bool independentReview) {
        if (appId == bytes32(0) || workflowKey == bytes32(0)) revert AVACoreTypes.EmptyValue();
        APP_ID = appId;
        WORKFLOW_KEY = workflowKey;
        INDEPENDENT_REVIEW = independentReview;
    }

    function validateProcedureReview(Review calldata review) external view {
        if (
            review.appId != APP_ID || review.workflowKey != WORKFLOW_KEY || review.packageId == 0
                || review.decisionId == 0 || review.challengeId == 0 || review.reasonHash == bytes32(0)
                || review.resolver == address(0) || review.evaluatedAt != block.timestamp
                || (INDEPENDENT_REVIEW
                    && (review.resolver == review.originalActor || review.resolver == review.challenger))
        ) {
            revert AVACoreTypes.InvalidState(review.challengeId);
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(APP_ID, WORKFLOW_KEY, INDEPENDENT_REVIEW));
    }
}
