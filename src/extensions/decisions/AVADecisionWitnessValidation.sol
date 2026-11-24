// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../../core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {AVAIdentityRegistry} from "../../core/AVAIdentityRegistry.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../../core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {AVARequestAllocation} from "../requests/AVARequestAllocation.sol";

/// @notice Fixed live witness validation; delegation preserves the registry as the Core caller.
/// @dev No storage, authority or current eligibility cache is introduced here.
library AVADecisionWitnessValidation {
    /// @dev Delegation preserves the policy caller. This binds context and module,
    /// not the policy's parent call stack or witness provenance.
    function requireResolvedCallback(
        AVAGovernanceKernel kernel,
        address requestAllocation,
        IAVARequestPolicy.RequestContext memory context
    ) external view {
        IAVARequestPolicy.RequestContext memory stored = AVARequestAllocation(requestAllocation).SUPPORT()
            .requestContext(context.requestId);
        if (keccak256(abi.encode(context)) != keccak256(abi.encode(stored))) {
            revert AVACoreTypes.InvalidState(context.requestId);
        }
        address policy = kernel.RULE_PACKAGE_REGISTRY().getModule(stored.packageId, AVACapabilityKeys.ALLOCATION);
        if (msg.sender != policy) revert AVACoreTypes.NotAuthorised(msg.sender, AVACoreTypes.ACTION_RECORD_ALLOCATION);
    }

    function resolve(
        AVAGovernanceKernel kernel,
        IAVADecisionPolicy.Request memory request,
        IAVARequestPolicy.WitnessInput memory input
    ) external view returns (IAVARequestPolicy.Witness memory witness, bool eligible) {
        AVAGovernanceKernel.RecognisedStateReference memory state =
            kernel.getRecognisedStateReference(input.recognisedStateId);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory packageContext =
            kernel.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(state.packageId);
        return _resolve(kernel, request, input, state, packageContext);
    }

    /// @notice Admit the full sorted pool, reusing only package verification within this invocation.
    /// @dev Reject each invalid or unavailable member before inspecting any later member.
    function validateAdmission(
        AVAGovernanceKernel kernel,
        IAVADecisionPolicy.Request memory request,
        IAVARequestPolicy.WitnessInput[] memory input
    ) external view {
        AVACoreRulePackageRegistry.VerifiedPackageContext[] memory contexts =
            new AVACoreRulePackageRegistry.VerifiedPackageContext[](input.length);
        uint256 contextCount;
        uint256 previousId;
        for (uint256 i; i < input.length; ++i) {
            if (input[i].recognisedStateId <= previousId) revert AVACoreTypes.InvalidState(input[i].recognisedStateId);
            previousId = input[i].recognisedStateId;
            AVAGovernanceKernel.RecognisedStateReference memory state =
                kernel.getRecognisedStateReference(input[i].recognisedStateId);
            AVACoreRulePackageRegistry.VerifiedPackageContext memory packageContext;
            bool verified;
            for (uint256 j; j < contextCount; ++j) {
                if (contexts[j].packageId == state.packageId) {
                    packageContext = contexts[j];
                    verified = true;
                    break;
                }
            }
            if (!verified) {
                packageContext = kernel.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(state.packageId);
                contexts[contextCount++] = packageContext;
            }
            (, bool eligible) = _resolve(kernel, request, input[i], state, packageContext);
            if (!eligible) revert AVACoreTypes.InvalidState(input[i].recognisedStateId);
        }
    }

    /// @notice Resolve the complete declared pool, checking each distinct source package once in this invocation.
    function resolveEligible(
        AVAGovernanceKernel kernel,
        IAVADecisionPolicy.Request memory request,
        IAVARequestPolicy.WitnessInput[] memory input
    ) external view returns (IAVARequestPolicy.Witness[] memory result) {
        result = new IAVARequestPolicy.Witness[](input.length);
        AVACoreRulePackageRegistry.VerifiedPackageContext[] memory contexts =
            new AVACoreRulePackageRegistry.VerifiedPackageContext[](input.length);
        uint256 contextCount;
        uint256 count;
        for (uint256 i; i < input.length; ++i) {
            AVAGovernanceKernel.RecognisedStateReference memory state =
                kernel.getRecognisedStateReference(input[i].recognisedStateId);
            AVACoreRulePackageRegistry.VerifiedPackageContext memory packageContext;
            bool verified;
            for (uint256 j; j < contextCount; ++j) {
                if (contexts[j].packageId == state.packageId) {
                    packageContext = contexts[j];
                    verified = true;
                    break;
                }
            }
            if (!verified) {
                packageContext = kernel.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(state.packageId);
                contexts[contextCount++] = packageContext;
            }
            (IAVARequestPolicy.Witness memory witness, bool eligible) =
                _resolve(kernel, request, input[i], state, packageContext);
            if (eligible) result[count++] = witness;
        }
        assembly ("memory-safe") {
            mstore(result, count)
        }
    }

    function _resolve(
        AVAGovernanceKernel kernel,
        IAVADecisionPolicy.Request memory request,
        IAVARequestPolicy.WitnessInput memory input,
        AVAGovernanceKernel.RecognisedStateReference memory state,
        AVACoreRulePackageRegistry.VerifiedPackageContext memory packageContext
    ) private view returns (IAVARequestPolicy.Witness memory witness, bool eligible) {
        (AVAGovernanceKernel.GovernedObjectReference memory objectRecord,, bytes32 metadataHash) =
            kernel.getGovernedObjectCommitmentReference(state.governedObjectId);
        AVAIdentityRegistry.SubjectContext memory subject = kernel.IDENTITY_REGISTRY().getSubjectContext(state.subjectId);
        AVAEvidenceRegistry.EvidenceReference memory evidence =
            kernel.EVIDENCE_REGISTRY().getEvidenceReference(state.evidenceReceiptId);
        if (
            state.appId != request.appId || state.workflowKey != request.workflowKey
                || packageContext.appId != state.appId || packageContext.workflowKey != state.workflowKey
                || objectRecord.appId != state.appId || objectRecord.workflowKey != state.workflowKey
                || objectRecord.packageId != state.packageId || objectRecord.subjectId != state.subjectId
                || subject.appId != state.appId || evidence.appId != state.appId
                || evidence.workflowKey != state.workflowKey || evidence.packageId != state.packageId
                || input.scope.claimHash == bytes32(0) || input.scope.useHash == bytes32(0)
                || input.scope.burdenHash == bytes32(0) || input.transitionId == 0
                || metadataHash != keccak256(abi.encode(keccak256("ava.recognition-scope.v1"), input.scope))
        ) revert AVACoreTypes.InvalidState(state.id);
        witness = IAVARequestPolicy.Witness(
            state.id,
            input.transitionId,
            state.governedObjectId,
            state.packageId,
            objectRecord.objectTypeKey,
            state.subjectId,
            state.evidenceReceiptId,
            input.scope
        );
        eligible = state.stage == AVACoreTypes.Stage.Verification
            && (state.status == AVACoreTypes.RecognisedStateStatus.Vested
                || state.status == AVACoreTypes.RecognisedStateStatus.Restored)
            && state.lastTransitionId == input.transitionId;
        bool dependenciesCurrent = kernel.DEPENDENCIES().dependenciesCurrent(state.governedObjectId);
        eligible = eligible && dependenciesCurrent;
        if (eligible) {
            eligible =
                kernel.EVIDENCE_REGISTRY().isEvidenceAvailableForPackage(state.evidenceReceiptId, state.packageId);
        }
    }
}
