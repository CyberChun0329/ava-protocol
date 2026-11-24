// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";

interface IAVADecisionRegistry {
    function REQUEST_ALLOCATION() external view returns (address);
    function validateExecutionSupport(
        IAVARequestPolicy.RequestContext calldata request,
        IAVARequestPolicy.Witness[] calldata witness
    ) external view;
    function validateExecutionDecision(
        IAVARequestPolicy.RequestContext calldata request,
        IAVARequestPolicy.DecisionContext calldata decision
    ) external view;
}

interface IAVADecisionExecutionPolicy {
    function DECISION_REGISTRY() external view returns (address);
}
