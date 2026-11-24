// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {IAVAEvidencePolicyModule, IAVADisclosurePolicyModule} from "../../core/interfaces/IAVACoreRuleModules.sol";
import {IAVAApplicationModule} from "../../interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice Requires encrypted-record evidence and one disclosure policy in a scoped workflow.
/// @dev The commitment is SHA-256 of the encrypted envelope, never of plaintext or human identity.
/// Core contexts expose no file bytes: this module cannot inspect encryption, AEAD validity, URI
/// contents or identity separation. The trusted off-chain custodian must enforce those properties.
contract AVAConfidentialEvidencePolicy is IAVAEvidencePolicyModule, IAVADisclosurePolicyModule, RuleModuleIdentity {
    bytes32 public constant SHA256_ENCRYPTED_ENVELOPE = keccak256("sha256.encrypted-envelope.v1");
    bytes32 public immutable EXPECTED_APP;
    bytes32 public immutable WORKFLOW_KEY;
    uint256 public immutable DISCLOSURE_POLICY_ID;

    constructor(bytes32 expectedApp_, bytes32 workflowKey_, uint256 disclosurePolicyId_) {
        if (expectedApp_ == bytes32(0) || workflowKey_ == bytes32(0) || disclosurePolicyId_ == 0) {
            revert AVACoreTypes.EmptyValue();
        }
        EXPECTED_APP = expectedApp_;
        WORKFLOW_KEY = workflowKey_;
        DISCLOSURE_POLICY_ID = disclosurePolicyId_;
    }

    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata context) external view {
        _validate(
            context.appId, context.workflowKey, context.disclosurePolicyId, context.evidenceTypeHash, context.packageId
        );
    }

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) public view virtual {
        _validate(
            context.appId, context.workflowKey, context.disclosurePolicyId, context.evidenceTypeHash, context.evidenceId
        );
    }

    function validateDisclosure(DisclosureContext calldata context) public view virtual {
        _validate(
            context.appId, context.workflowKey, context.disclosurePolicyId, context.evidenceTypeHash, context.targetId
        );
    }

    function _validate(bytes32 appId, bytes32 workflowKey, uint256 disclosurePolicyId, bytes32 evidenceType, uint256 id)
        private
        view
    {
        if (
            appId != EXPECTED_APP || workflowKey != WORKFLOW_KEY || disclosurePolicyId != DISCLOSURE_POLICY_ID
                || evidenceType != SHA256_ENCRYPTED_ENVELOPE
        ) revert AVACoreTypes.InvalidState(id);
    }

    function _moduleConfigurationHash() internal view virtual override returns (bytes32) {
        return keccak256(abi.encode(EXPECTED_APP, WORKFLOW_KEY, DISCLOSURE_POLICY_ID, SHA256_ENCRYPTED_ENVELOPE));
    }
}
