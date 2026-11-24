// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {IAVAAllocationPolicyModule} from "../../core/interfaces/IAVACoreRuleModules.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {IAVADecisionRegistry} from "./IAVADecisionRegistry.sol";

interface IDecisionRequestOwner {
    function SUPPORT() external view returns (address);
}

/// @notice Binds the existing request/effect lifecycle to an explicit full-set decision selection.
contract AVARecognisedDecisionPolicy is IAVARequestPolicy, IAVAAllocationPolicyModule, RuleModuleIdentity {
    address public immutable DECISION_REGISTRY;
    address public immutable REQUEST_ALLOCATION;
    error InvalidDecisionBinding();

    constructor(IAVADecisionRegistry registry) {
        if (address(registry).code.length == 0) revert InvalidDecisionBinding();
        address requests = registry.REQUEST_ALLOCATION();
        if (requests.code.length == 0) revert InvalidDecisionBinding();
        DECISION_REGISTRY = address(registry);
        REQUEST_ALLOCATION = requests;
    }

    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external view {
        _requireBoundCaller(request);
        IAVADecisionRegistry(DECISION_REGISTRY).validateExecutionSupport(request, witness);
    }

    function validateRequestAllocation(
        RequestContext calldata request,
        Witness[] calldata,
        DecisionContext calldata decision
    ) external view virtual {
        _requireBoundCaller(request);
        if (decision.evaluatedAt != block.timestamp) revert InvalidDecisionBinding();
        // Support already checked the full catalogue in this view. The registry
        // freshly resolves and checks the selected witness and current decision.
        IAVADecisionRegistry(DECISION_REGISTRY).validateExecutionDecision(request, decision);
    }

    // Canonical actor and application policy checks run in the existing downstream base;
    // full request/selection checks run in the typed callback above.
    function validateAllocation(AllocationPolicyContext calldata context) external pure {
        if (context.units != 1) revert InvalidDecisionBinding();
    }

    function _requireBoundCaller(RequestContext calldata request) internal view {
        if (request.requestAllocation != REQUEST_ALLOCATION) revert InvalidDecisionBinding();
        if (msg.sender != REQUEST_ALLOCATION && msg.sender != IDecisionRequestOwner(REQUEST_ALLOCATION).SUPPORT()) {
            revert InvalidDecisionBinding();
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(DECISION_REGISTRY, REQUEST_ALLOCATION));
    }
}
