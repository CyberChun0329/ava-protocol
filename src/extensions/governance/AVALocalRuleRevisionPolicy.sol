// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAIdentityRegistry} from "../../core/AVAIdentityRegistry.sol";
import {IAVARuleRevisionPolicy} from "../../core/interfaces/IAVARuleRevisionPolicy.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice One explicit local choice; AVA does not prescribe its delay or independence requirements.
contract AVALocalRuleRevisionPolicy is IAVARuleRevisionPolicy, RuleModuleIdentity {
    uint256 public constant MAX_REVISER_SUBJECTS = 32;
    AVAIdentityRegistry public immutable IDENTITY_REGISTRY;
    bytes32 public immutable APP_ID;
    bytes32 public immutable GOVERNANCE_WORKFLOW_KEY;
    uint64 public immutable MIN_DELAY;
    bool public immutable INDEPENDENT_FROM_PROPOSER;
    bool public immutable INDEPENDENT_FROM_RECOGNISER;
    bytes32 public immutable ALLOWED_SUBJECTS_HASH;
    uint256 public immutable ALLOWED_SUBJECTS_COUNT;
    mapping(bytes32 => bool) public isAllowedSubject;

    constructor(
        AVAIdentityRegistry identityRegistry,
        bytes32 appId,
        bytes32 governingWorkflowKey,
        uint64 minDelay,
        bool independentFromProposer,
        bool independentFromRecogniser,
        bytes32[] memory allowedSubjectIds
    ) {
        if (
            address(identityRegistry).code.length == 0 || appId == bytes32(0) || governingWorkflowKey == bytes32(0)
                || allowedSubjectIds.length == 0 || allowedSubjectIds.length > MAX_REVISER_SUBJECTS
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        for (uint256 i; i < allowedSubjectIds.length; ++i) {
            bytes32 subjectId = allowedSubjectIds[i];
            AVAIdentityRegistry.SubjectContext memory subject =
                identityRegistry.requireActiveSubjectContext(subjectId, appId);
            if (
                isAllowedSubject[subjectId]
                    || identityRegistry.subjectOf(subject.account, appId, subject.roleKey) != subjectId
            ) revert AVACoreTypes.InvalidState(uint256(subjectId));
            isAllowedSubject[subjectId] = true;
        }
        IDENTITY_REGISTRY = identityRegistry;
        APP_ID = appId;
        GOVERNANCE_WORKFLOW_KEY = governingWorkflowKey;
        MIN_DELAY = minDelay;
        INDEPENDENT_FROM_PROPOSER = independentFromProposer;
        INDEPENDENT_FROM_RECOGNISER = independentFromRecogniser;
        ALLOWED_SUBJECTS_HASH = keccak256(abi.encode(allowedSubjectIds));
        ALLOWED_SUBJECTS_COUNT = allowedSubjectIds.length;
    }

    function validateRuleRevision(RuleRevisionContext calldata context) external view {
        if (
            context.appId != APP_ID || context.governingWorkflowKey != GOVERNANCE_WORKFLOW_KEY
                || !isAllowedSubject[context.actorAuthorityId]
                || uint256(context.evaluatedAt) < uint256(context.submittedAt) + MIN_DELAY
                || (INDEPENDENT_FROM_PROPOSER && context.actor == context.proposer)
                || (INDEPENDENT_FROM_RECOGNISER
                    && (context.actor == context.recognisedBy || context.actor == context.sourceDecisionActor))
        ) revert AVACoreTypes.InvalidState(context.proposalId);
        // Subject account/application fields cannot be reassigned. A new subject needs a new governed policy.
        AVAIdentityRegistry.SubjectContext memory actor = IDENTITY_REGISTRY.getSubjectContext(context.actorAuthorityId);
        if (actor.appId != APP_ID || actor.account != context.actor) {
            revert AVACoreTypes.InvalidState(context.proposalId);
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(
            abi.encode(
                address(IDENTITY_REGISTRY),
                APP_ID,
                GOVERNANCE_WORKFLOW_KEY,
                MIN_DELAY,
                INDEPENDENT_FROM_PROPOSER,
                INDEPENDENT_FROM_RECOGNISER,
                ALLOWED_SUBJECTS_HASH
            )
        );
    }
}
