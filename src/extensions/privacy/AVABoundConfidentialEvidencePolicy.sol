// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {IAVAApplicationModule} from "../../interfaces/IAVAApplicationModule.sol";
import {AVAConfidentialEvidencePolicy} from "./AVAConfidentialEvidencePolicy.sol";
import {AVAEvidenceResourceBinding} from "./AVAEvidenceResourceBinding.sol";

/// @notice Confidential evidence whose exact Core/private-resource binding is checked on use.
contract AVABoundConfidentialEvidencePolicy is AVAConfidentialEvidencePolicy {
    bytes32 private constant ACTION_REQUIRE_USABLE_EVIDENCE = keccak256("ava.core.require-usable-evidence.v1");
    AVAEvidenceResourceBinding public immutable BINDINGS;
    uint256 public immutable PRIVACY_POLICY_ID;

    constructor(
        bytes32 appId_,
        bytes32 workflowKey_,
        uint256 disclosurePolicyId_,
        AVAEvidenceResourceBinding bindings_,
        uint256 privacyPolicyId_
    ) AVAConfidentialEvidencePolicy(appId_, workflowKey_, disclosurePolicyId_) {
        if (address(bindings_).code.length == 0 || privacyPolicyId_ == 0) {
            revert AVACoreTypes.EmptyValue();
        }
        (bytes32 policyApp,) = bindings_.PRIVACY_REGISTRY().policyContext(privacyPolicyId_);
        if (policyApp != appId_) revert AVACoreTypes.CrossApplicationReference(appId_, policyApp);
        BINDINGS = bindings_;
        PRIVACY_POLICY_ID = privacyPolicyId_;
    }

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) public view override {
        super.validateEvidenceUse(context);
        _requireContext(
            context.evidenceId,
            context.packageId,
            context.subjectId,
            context.actionKey == ACTION_REQUIRE_USABLE_EVIDENCE
        );
    }

    function validateDisclosure(DisclosureContext calldata context) public view override {
        super.validateDisclosure(context);
        // Registration has no allocated evidence ID yet; binding must precede any later use.
        if (context.evidenceId != 0) {
            _requireContext(
                context.evidenceId,
                context.packageId,
                context.subjectId,
                context.actionKey == ACTION_REQUIRE_USABLE_EVIDENCE
            );
        }
    }

    function _requireContext(uint256 evidenceId, uint256 packageId, bytes32 subjectId, bool current) private view {
        AVAEvidenceResourceBinding.Binding memory binding;
        bool usable;
        if (current) (binding, usable) = BINDINGS.bindingStatus(evidenceId);
        else binding = BINDINGS.requireBinding(evidenceId);
        if (
            binding.appId != EXPECTED_APP || binding.workflowKey != WORKFLOW_KEY || binding.packageId != packageId
                || binding.subjectId != subjectId || binding.disclosurePolicyId != DISCLOSURE_POLICY_ID
                || binding.privacyPolicyId != PRIVACY_POLICY_ID
        ) revert AVACoreTypes.InvalidState(evidenceId);
        // Validate exact scope before reporting known unavailability, so a retired foreign or
        // mismatched binding cannot masquerade as an ordinary unavailable candidate.
        if (current && !usable) revert AVACoreTypes.EvidenceUnavailable(evidenceId);
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(super._moduleConfigurationHash(), BINDINGS, PRIVACY_POLICY_ID));
    }
}
