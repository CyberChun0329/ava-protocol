// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";

library AVAExecutionApproval {
    bytes32 internal constant CAPABILITY = keccak256("ava.extension.request.execution-approval.v1");
}

/// @notice Optional package policy for retaining an already approved request's execution authority.
/// @dev A successful check replaces only the current allocator authority requirement at execution.
interface IAVAExecutionApprovalPolicy {
    function validateExecutionApproval(
        IAVARequestPolicy.RequestContext calldata request,
        IAVARequestPolicy.DecisionContext calldata decision
    ) external view;
}
