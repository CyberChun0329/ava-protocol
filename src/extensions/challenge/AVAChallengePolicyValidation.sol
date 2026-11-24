// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVAWorkflowPolicyRouter} from "../../core/AVAWorkflowPolicyRouter.sol";
import {AVAChallengeExtension} from "./AVAChallengeExtension.sol";

/// @notice Fixed filing-policy validation; delegation retains the Challenge caller and original actor.
/// @dev No storage, authority, module selection or replaceable binding is introduced here.
library AVAChallengePolicyValidation {
    function validateFiling(
        AVAGovernanceKernel kernel,
        AVAWorkflowPolicyRouter router,
        bytes32 appId,
        bytes32 workflowKey,
        uint256 packageId,
        bytes32 roleKey,
        AVAGovernanceKernel.RecognisedStateReference memory challengeState,
        bytes32 challengeObjectTypeKey,
        AVAGovernanceKernel.RecognisedStateReference memory target
    ) external view {
        AVAGovernanceKernel.GovernedObjectReference memory targetObject =
            kernel.getGovernedObjectReference(target.governedObjectId);
        AVAWorkflowPolicyRouter.ChallengePolicyInput memory policy;
        policy.appId = appId;
        policy.workflowKey = workflowKey;
        policy.packageId = packageId;
        policy.actionKey = AVACoreTypes.ACTION_FILE_CHALLENGE;
        policy.roleKey = roleKey;
        policy.stage = AVACoreTypes.Stage.Verification;
        policy.objectTypeKey = challengeObjectTypeKey;
        policy.recognisedStateId = target.id;
        policy.actorSubjectId = challengeState.subjectId;
        policy.targetSubjectId = target.subjectId;
        policy.targetStatus = target.status;
        policy.evidenceId = challengeState.evidenceReceiptId;
        policy.disclosurePolicyId = challengeState.disclosurePolicyId;
        policy.authorityId = challengeState.subjectId;
        policy.actor = msg.sender;
        router.validateChallengePolicies(policy);
        if (target.packageId != packageId) {
            policy.appId = target.appId;
            policy.workflowKey = target.workflowKey;
            policy.packageId = target.packageId;
            policy.stage = target.stage;
            policy.objectTypeKey = targetObject.objectTypeKey;
            policy.evidenceId = 0;
            policy.disclosurePolicyId = 0;
            router.validateChallengePolicies(policy);
        }
    }

    function validateStored(
        AVAGovernanceKernel kernel,
        AVAEvidenceRegistry evidence,
        AVAWorkflowPolicyRouter router,
        AVAChallengeExtension.ChallengeRecord storage challenge,
        AVAChallengeExtension.StoredPolicyInput memory input
    ) external view {
        AVAGovernanceKernel.RecognisedStateReference memory target =
            kernel.getRecognisedStateReference(challenge.challengedRecognisedStateId);
        bytes32 objectTypeKey = kernel.getGovernedObjectReference(target.governedObjectId).objectTypeKey;
        bytes32 decisionHash = keccak256(
            abi.encode(
                challenge.id,
                input.actionKey,
                target.lastTransitionId,
                input.outcome,
                input.reasonHash,
                challenge.packageId,
                challenge.targetPackageId,
                challenge.evidenceReceiptId,
                challenge.decisionEvidenceReceiptId
            )
        );
        AVAWorkflowPolicyRouter.ChallengePolicyInput memory policy;
        policy.appId = challenge.appId;
        policy.workflowKey = challenge.workflowKey;
        policy.packageId = challenge.packageId;
        policy.actionKey = input.actionKey;
        policy.roleKey = input.roleKey;
        policy.stage = target.stage;
        policy.objectTypeKey = objectTypeKey;
        policy.challengeId = challenge.id;
        policy.recognisedStateId = target.id;
        policy.actorSubjectId = input.authorityId;
        policy.targetSubjectId = target.subjectId;
        policy.outcomeKey = bytes32(uint256(uint8(input.outcome)));
        policy.targetStatus = target.status;
        policy.evidenceId = input.actionKey == AVACoreTypes.ACTION_RESOLVE_CHALLENGE
            || challenge.outcome != AVAChallengeExtension.ChallengeOutcome.None
            ? challenge.decisionEvidenceReceiptId
            : challenge.evidenceReceiptId;
        policy.disclosurePolicyId =
            policy.evidenceId == 0 ? 0 : evidence.getEvidenceReference(policy.evidenceId).disclosurePolicyId;
        policy.authorityId = input.authorityId;
        policy.decisionHash = decisionHash;
        policy.actor = input.authorityActor;
        policy.validateAuthority = true;
        router.validateChallengePolicies(policy);
        if (challenge.targetPackageId != challenge.packageId) {
            policy.appId = target.appId;
            policy.workflowKey = target.workflowKey;
            policy.packageId = challenge.targetPackageId;
            policy.evidenceId = 0;
            policy.disclosurePolicyId = 0;
            router.validateChallengePolicies(policy);
        }
    }
}
