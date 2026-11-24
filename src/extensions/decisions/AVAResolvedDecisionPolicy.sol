// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVARecognisedDecisionPolicy} from "./AVARecognisedDecisionPolicy.sol";
import {IAVAResolvedDecisionRegistry} from "./IAVAResolvedDecisionRegistry.sol";

/// @notice Optional builtin policy for registries exposing resolved-witness callbacks.
/// @dev Legacy/custom registries can continue using AVARecognisedDecisionPolicy unchanged.
contract AVAResolvedDecisionPolicy is AVARecognisedDecisionPolicy {
    constructor(IAVAResolvedDecisionRegistry registry) AVARecognisedDecisionPolicy(registry) {
        if (
            registry.RESOLVED_DECISION_CALLBACK()
                != IAVAResolvedDecisionRegistry.validateResolvedExecutionDecision.selector
        ) revert InvalidDecisionBinding();
    }

    function validateRequestAllocation(
        RequestContext calldata request,
        Witness[] calldata witness,
        DecisionContext calldata decision
    ) external view override {
        _requireBoundCaller(request);
        if (decision.evaluatedAt != block.timestamp) revert InvalidDecisionBinding();
        IAVAResolvedDecisionRegistry registry = IAVAResolvedDecisionRegistry(DECISION_REGISTRY);
        if (msg.sender == REQUEST_ALLOCATION) {
            // Direct compatibility calls have no preceding canonical Support resolution.
            registry.validateExecutionDecision(request, decision);
        } else {
            // _requireBoundCaller established canonical Support. Its mandatory checks
            // ran before this callback; the registry still resolves the generic pool.
            registry.validateResolvedExecutionDecision(request, witness, decision);
        }
    }
}
