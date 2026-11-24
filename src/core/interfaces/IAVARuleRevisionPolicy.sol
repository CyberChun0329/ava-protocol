// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IRuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice A separately declared revision authority, evaluated under the OLD governing package.
interface IAVARuleRevisionPolicy is IRuleModuleIdentity {
    struct RuleRevisionContext {
        bytes32 appId;
        bytes32 governingWorkflowKey;
        bytes32 targetWorkflowKey;
        uint256 governancePackageId;
        uint256 targetPackageId;
        bytes32 oldGovernanceAuthorityId;
        bytes32 oldTargetAuthorityId;
        uint256 proposalId;
        uint256 sourceStateId;
        uint256 sourceObjectId;
        uint256 sourceTransitionId;
        bytes32 sourceSubjectId;
        bytes32 revisionCommitment;
        bytes32 proposalCommitment;
        uint64 proposedVersion;
        bytes32 proposedAuthorityId;
        bytes32 proposedRoleKey;
        uint256 correctionOfAppliedProposal;
        address proposer;
        bytes32 proposerAuthorityId;
        address recognisedBy;
        address sourceDecisionActor;
        address actor;
        bytes32 actorRoleKey;
        bytes32 actorAuthorityId;
        uint64 recognisedAt;
        uint64 submittedAt;
        uint64 evaluatedAt;
    }

    function validateRuleRevision(RuleRevisionContext calldata context) external view;
}
