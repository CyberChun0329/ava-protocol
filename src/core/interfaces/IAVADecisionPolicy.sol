// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IRuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {IAVARequestPolicy} from "./IAVARequestPolicy.sol";

/// @notice Complete finite Y_q, its Allocation predicate and witness resolver for a declared domain.
/// @dev Returning a shortlist or one preferred choice violates this interface's catalogue contract.
interface IAVADecisionPolicy is IRuleModuleIdentity {
    enum Kind {
        Substantive,
        Withhold,
        Pause,
        SeekEvidence,
        Escalate,
        Resume,
        Close
    }

    struct Request {
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        bytes32 requestHash;
        address executor;
        bytes32 responseClass;
        bytes32 burdenHash;
        uint64 validUntil;
    }

    struct Option {
        bytes32 key;
        Kind kind;
        bytes32 actionKey;
        bytes32 parametersHash;
        uint64 notBefore;
        bytes32 conditionsHash;
    }

    struct Actor {
        address account;
        bytes32 roleKey;
        bytes32 authorityId;
        uint64 evaluatedAt;
    }

    struct Process {
        uint256 requestId;
        uint256 lastDecisionId;
        uint256 allocationDecisionId;
        uint256 executionRequestId;
        uint256 supportRevision;
        bool paused;
        bool closed;
    }
    function catalogue(Request calldata request) external view returns (Option[] memory);
    function ruleValid(Request calldata request, uint64 evaluatedAt) external view returns (bool);
    function allocationAllowed(
        Request calldata request,
        Process calldata process,
        Actor calldata actor,
        Option calldata option
    ) external view returns (bool);
    /// @dev Indices into the declared request's current eligible pool, strictly increasing.
    /// Empty means no witness. It must resolve existential support over this domain's declared pool.
    function witnessFor(Request calldata request, Option calldata option, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        returns (uint256[] memory);
}
