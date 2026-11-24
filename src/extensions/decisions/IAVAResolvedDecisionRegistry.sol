// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVADecisionRegistry} from "./IAVADecisionRegistry.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";

/// @notice Optional policy callback using execution witnesses already resolved by canonical Support.
interface IAVAResolvedDecisionRegistry is IAVADecisionRegistry {
    /// @notice Declares this optional callback interface for installation compatibility.
    function RESOLVED_DECISION_CALLBACK() external view returns (bytes4);

    /// @dev The caller is the verified allocation policy; this does not attest its parent call stack.
    /// Mandatory Core support resolution remains a prerequisite of approval and consumption.
    function validateResolvedExecutionDecision(
        IAVARequestPolicy.RequestContext calldata request,
        IAVARequestPolicy.Witness[] calldata witness,
        IAVARequestPolicy.DecisionContext calldata decision
    ) external view;
}
