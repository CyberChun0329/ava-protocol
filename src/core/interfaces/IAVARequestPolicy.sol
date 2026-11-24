// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IRuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice Typed request support and actor-specific decision checks. Neither confers recognition.
interface IAVARequestPolicy is IRuleModuleIdentity {
    struct RecognitionScope {
        bytes32 claimHash;
        bytes32 useHash;
        bytes32 burdenHash;
    }

    struct WitnessInput {
        uint256 recognisedStateId;
        uint256 transitionId;
        RecognitionScope scope;
    }

    struct Witness {
        uint256 recognisedStateId;
        uint256 transitionId;
        uint256 governedObjectId;
        uint256 packageId;
        bytes32 objectTypeKey;
        bytes32 subjectId;
        uint256 evidenceReceiptId;
        RecognitionScope scope;
    }

    struct RequestContext {
        address requestAllocation;
        uint256 requestId;
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        uint256 primaryRecognisedStateId;
        address executor;
        bytes32 responseClass;
        bytes32 parametersHash;
        bytes32 burdenHash;
        uint64 validUntil;
        bytes32 commitment;
        bool exactCommitment;
    }

    struct DecisionContext {
        bytes32 roleKey;
        bytes32 authorityId;
        address actor;
        uint64 evaluatedAt;
    }

    /// @dev Actor-neutral matching and joint sufficiency under the selected rule.
    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external view;

    /// @dev Checks the concrete positive response selection, separately from support and execution.
    function validateRequestAllocation(
        RequestContext calldata request,
        Witness[] calldata witness,
        DecisionContext calldata decision
    ) external view;
}
