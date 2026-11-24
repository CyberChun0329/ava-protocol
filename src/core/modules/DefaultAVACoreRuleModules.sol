// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IAVARequestPolicy} from "../interfaces/IAVARequestPolicy.sol";
import {IAVAApplicationModule} from "../../interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {
    IAVAAttributionModule,
    IAVAVerificationModule,
    IAVATransitionRuleModule,
    IAVAEvidencePolicyModule,
    IAVAEvidenceLifecycleModule,
    IAVADisclosurePolicyModule,
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAStandingPolicyModule,
    IAVAAllocationPolicyModule,
    IAVAConsequencePolicyModule,
    IAVAFieldPolicyModule,
    IAVAAntiAbusePolicyModule
} from "../interfaces/IAVACoreRuleModules.sol";

/// @notice Structural exact-request checks only; no institutional sufficiency judgment.
interface IAVARequestSupportOwner {
    function SUPPORT() external view returns (address);
}

abstract contract DefaultCoreExactRequestPolicy is IAVARequestPolicy {
    error InvalidRequestPolicyContext(uint256 requestId);

    function validateResponseSupport(RequestContext calldata request, Witness[] calldata witness) external view {
        _validateResponseSupport(request, witness);
    }

    function validateRequestAllocation(
        RequestContext calldata request,
        Witness[] calldata witness,
        DecisionContext calldata decision
    ) external view {
        _validateResponseSupport(request, witness);
        // Canonical role/action authority is checked by the request extension.
        if (
            decision.roleKey == bytes32(0) || decision.authorityId == bytes32(0) || decision.actor == address(0)
                || decision.evaluatedAt != block.timestamp
        ) revert InvalidRequestPolicyContext(request.requestId);
    }

    function _isRequestCaller(address extension) private view returns (bool) {
        if (msg.sender == extension) return true;
        try IAVARequestSupportOwner(extension).SUPPORT() returns (address support) {
            return support != address(0) && msg.sender == support;
        } catch {
            return false;
        }
    }

    function _validateResponseSupport(RequestContext calldata request, Witness[] calldata witness)
        internal
        view
        virtual
    {
        if (
            !_isRequestCaller(request.requestAllocation) || request.requestAllocation == address(0)
                || request.requestId == 0 || request.appId == bytes32(0) || request.workflowKey == bytes32(0)
                || request.packageId == 0 || request.primaryRecognisedStateId == 0 || request.executor == address(0)
                || request.responseClass == bytes32(0) || request.parametersHash == bytes32(0)
                || request.burdenHash == bytes32(0) || request.validUntil <= block.timestamp || !request.exactCommitment
                || witness.length != 1
        ) revert InvalidRequestPolicyContext(request.requestId);
        Witness calldata source = witness[0];
        if (
            source.recognisedStateId != request.primaryRecognisedStateId || source.transitionId == 0
                || source.governedObjectId == 0 || source.packageId != request.packageId
                || source.objectTypeKey == bytes32(0) || source.subjectId == bytes32(0) || source.evidenceReceiptId == 0
                || source.scope.claimHash != request.commitment || source.scope.useHash != request.responseClass
                || source.scope.burdenHash != request.burdenHash
                || request.commitment
                    != keccak256(
                        abi.encode(
                            keccak256("ava.request-allocation.commitment.v1"),
                            block.chainid,
                            request.requestAllocation,
                            request.appId,
                            request.executor,
                            request.responseClass,
                            request.parametersHash,
                            request.burdenHash,
                            request.validUntil
                        )
                    )
        ) revert InvalidRequestPolicyContext(request.requestId);
    }
}

/// @notice Shared stateless implementation for the default core policy capabilities.
/// @dev Capability keys remain independently bound and replaceable in each rule package.
contract DefaultAVACorePolicyBundle is
    IAVAAttributionModule,
    IAVAVerificationModule,
    IAVATransitionRuleModule,
    IAVAEvidencePolicyModule,
    IAVAEvidenceLifecycleModule,
    IAVADisclosurePolicyModule,
    IAVAChallengePolicyModule,
    IAVAAuthorityPolicyModule,
    IAVAStandingPolicyModule,
    IAVAAllocationPolicyModule,
    DefaultCoreExactRequestPolicy,
    IAVAConsequencePolicyModule,
    IAVAFieldPolicyModule,
    IAVAAntiAbusePolicyModule,
    RuleModuleIdentity
{
    function validateAttribution(IAVAApplicationModule.GovernedObjectContext calldata) external pure {}

    function validateVerification(IAVAApplicationModule.RecognisedStateFormationContext calldata) external pure {}

    function validateTransition(IAVAApplicationModule.RecognisedStateTransitionContext calldata) external pure {}

    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata)
        external
        pure
        override(IAVAEvidencePolicyModule, IAVAEvidenceLifecycleModule)
    {}

    function validateEvidenceLifecycle(EvidenceLifecycleContext calldata) external pure {}

    function validateDisclosure(DisclosureContext calldata) external pure {}

    function validateChallenge(ChallengeContext calldata) external pure {}

    function validateAuthority(AuthorityContext calldata) external pure {}

    function validateStanding(StandingPolicyContext calldata) external pure {}

    function validateAllocation(AllocationPolicyContext calldata) external pure {}

    function validateConsequence(IAVAApplicationModule.DownstreamRecordContext calldata) external pure {}

    function validateFieldPolicy(FieldPolicyContext calldata) external pure {}

    function validateAntiAbuse(AntiAbuseContext calldata) external pure {}
}

contract DefaultCoreAttributionModule is IAVAAttributionModule, RuleModuleIdentity {
    function validateAttribution(IAVAApplicationModule.GovernedObjectContext calldata) external pure {}
}

contract DefaultCoreVerificationModule is IAVAVerificationModule, RuleModuleIdentity {
    function validateVerification(IAVAApplicationModule.RecognisedStateFormationContext calldata) external pure {}
}

contract DefaultCoreTransitionRuleModule is IAVATransitionRuleModule, RuleModuleIdentity {
    function validateTransition(IAVAApplicationModule.RecognisedStateTransitionContext calldata) external pure {}
}

contract DefaultCoreEvidencePolicyModule is IAVAEvidencePolicyModule, RuleModuleIdentity {
    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata) external pure {}
}

contract DefaultCoreEvidenceLifecycleModule is IAVAEvidenceLifecycleModule, RuleModuleIdentity {
    function validateEvidenceLifecycle(EvidenceLifecycleContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata) external pure {}
}

contract DefaultCoreDisclosurePolicyModule is IAVADisclosurePolicyModule, RuleModuleIdentity {
    function validateDisclosure(DisclosureContext calldata) external pure {}
}

contract DefaultCoreChallengePolicyModule is IAVAChallengePolicyModule, RuleModuleIdentity {
    function validateChallenge(ChallengeContext calldata) external pure {}
}

contract DefaultCoreAuthorityPolicyModule is IAVAAuthorityPolicyModule, RuleModuleIdentity {
    function validateAuthority(AuthorityContext calldata) external pure {}
}

contract DefaultCoreStandingPolicyModule is IAVAStandingPolicyModule, RuleModuleIdentity {
    function validateStanding(StandingPolicyContext calldata) external pure {}
}

contract DefaultCoreAllocationPolicyModule is
    IAVAAllocationPolicyModule,
    DefaultCoreExactRequestPolicy,
    RuleModuleIdentity
{
    function validateAllocation(AllocationPolicyContext calldata) external view virtual {}
}

contract DefaultCoreConsequencePolicyModule is IAVAConsequencePolicyModule, RuleModuleIdentity {
    function validateConsequence(IAVAApplicationModule.DownstreamRecordContext calldata) external pure {}
}
