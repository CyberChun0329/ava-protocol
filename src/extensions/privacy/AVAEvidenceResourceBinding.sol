// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {AVAPrivacyRegistry} from "./AVAPrivacyRegistry.sol";

/// @notice Immutable one-to-one links between Core receipts and encrypted private resources.
/// @dev The hash identifies the encrypted envelope. It proves neither plaintext nor encryption validity.
contract AVAEvidenceResourceBinding {
    bytes32 public constant BIND_EVIDENCE = keccak256("ava.privacy.bind-evidence.v1");
    bytes32 public constant SHA256_ENCRYPTED_ENVELOPE = keccak256("sha256.encrypted-envelope.v1");

    struct Binding {
        uint256 evidenceId;
        bytes32 resourceId;
        bytes32 appId;
        bytes32 caseId;
        uint256 privacyPolicyId;
        bytes32 materialClass;
        bytes32 ciphertextHash;
        bytes32 workflowKey;
        uint256 packageId;
        bytes32 subjectId;
        uint256 disclosurePolicyId;
    }

    AVAPrivacyRegistry public immutable PRIVACY_REGISTRY;
    AVAEvidenceRegistry public immutable EVIDENCE_REGISTRY;
    mapping(uint256 => Binding) private bindings;
    mapping(bytes32 => uint256) public evidenceByResource;

    event EvidenceBound(
        uint256 indexed evidenceId,
        bytes32 indexed resourceId,
        bytes32 indexed caseId,
        uint256 privacyPolicyId,
        bytes32 authorityId
    );

    constructor(AVAPrivacyRegistry privacy_, AVAEvidenceRegistry evidence_) {
        if (address(privacy_).code.length == 0 || address(evidence_).code.length == 0) {
            revert AVACoreTypes.EmptyValue();
        }
        if (address(privacy_.AUTHORITY_MATRIX()) != address(evidence_.AUTHORITY_MATRIX())) {
            revert AVACoreTypes.InvalidState(0);
        }
        PRIVACY_REGISTRY = privacy_;
        EVIDENCE_REGISTRY = evidence_;
    }

    function bindEvidence(uint256 evidenceId, bytes32 resourceId, bytes32 roleKey, bytes32 authorityId) external {
        _bindEvidence(evidenceId, resourceId, roleKey, authorityId);
    }

    struct BindingInput {
        uint256 evidenceId;
        bytes32 resourceId;
    }

    /// @notice Binds two independent evidence receipts to resources in one exact case.
    function bindEvidencePair(bytes32 caseId, BindingInput[2] calldata input, bytes32 roleKey, bytes32 authorityId)
        external
    {
        for (uint256 i; i < 2; ++i) {
            BindingInput calldata item = input[i];
            if (_bindEvidence(item.evidenceId, item.resourceId, roleKey, authorityId) != caseId) {
                revert AVACoreTypes.InvalidState(item.evidenceId);
            }
        }
    }

    function _bindEvidence(uint256 evidenceId, bytes32 resourceId, bytes32 roleKey, bytes32 authorityId)
        private
        returns (bytes32 caseId)
    {
        if (evidenceId == 0 || resourceId == bytes32(0) || roleKey == bytes32(0) || authorityId == bytes32(0)) {
            revert AVACoreTypes.EmptyValue();
        }
        if (bindings[evidenceId].evidenceId != 0 || evidenceByResource[resourceId] != 0) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
        AVACoreTypes.EvidenceRecord memory evidence = EVIDENCE_REGISTRY.getEvidence(evidenceId);
        PRIVACY_REGISTRY.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(msg.sender, evidence.appId, roleKey, BIND_EVIDENCE, authorityId);
        (
            bytes32 appId,
            bytes32 boundCaseId,
            uint256 privacyPolicyId,
            bytes32 materialClass,
            bytes32 ciphertextHash,
            bool active
        ) = PRIVACY_REGISTRY.resourceContext(resourceId);
        (bytes32 policyApp, bool policyActive) = PRIVACY_REGISTRY.policyContext(privacyPolicyId);
        if (
            appId != evidence.appId || policyApp != appId || !active || !policyActive
                || evidence.status != AVACoreTypes.EvidenceStatus.Active
                || evidence.evidenceTypeHash != SHA256_ENCRYPTED_ENVELOPE || evidence.commitment != ciphertextHash
                || keccak256(bytes(evidence.uri)) != keccak256(bytes(uriFor(resourceId)))
        ) revert AVACoreTypes.InvalidState(evidenceId);
        bindings[evidenceId] = Binding({
            evidenceId: evidenceId,
            resourceId: resourceId,
            appId: appId,
            caseId: boundCaseId,
            privacyPolicyId: privacyPolicyId,
            materialClass: materialClass,
            ciphertextHash: ciphertextHash,
            workflowKey: evidence.workflowKey,
            packageId: evidence.packageId,
            subjectId: evidence.subjectId,
            disclosurePolicyId: evidence.disclosurePolicyId
        });
        evidenceByResource[resourceId] = evidenceId;
        emit EvidenceBound(evidenceId, resourceId, boundCaseId, privacyPolicyId, authorityId);
        return boundCaseId;
    }

    /// @notice Exact historical context remains inspectable after evidence or resource retirement.
    function requireBinding(uint256 evidenceId) public view returns (Binding memory binding) {
        (binding,) = _bindingContext(evidenceId);
    }

    /// @dev Availability flags accompany the exact historical record; no current package check runs here.
    function _bindingContext(uint256 evidenceId) private view returns (Binding memory binding, bool active) {
        binding = bindings[evidenceId];
        if (binding.evidenceId == 0) revert AVACoreTypes.UnknownReference(evidenceId);
        AVACoreTypes.EvidenceRecord memory evidence = EVIDENCE_REGISTRY.getEvidence(evidenceId);
        (
            bytes32 appId,
            bytes32 caseId,
            uint256 policyId,
            bytes32 material,
            bytes32 ciphertextHash,
            bool resourceActive
        ) = PRIVACY_REGISTRY.resourceContext(binding.resourceId);
        (bytes32 policyApp, bool policyActive) = PRIVACY_REGISTRY.policyContext(policyId);
        if (
            evidenceByResource[binding.resourceId] != evidenceId || binding.appId != appId || policyApp != appId
                || binding.caseId != caseId || binding.privacyPolicyId != policyId || binding.materialClass != material
                || binding.ciphertextHash != ciphertextHash || evidence.appId != appId
                || evidence.workflowKey != binding.workflowKey || evidence.packageId != binding.packageId
                || evidence.subjectId != binding.subjectId || evidence.disclosurePolicyId != binding.disclosurePolicyId
                || evidence.commitment != ciphertextHash || evidence.evidenceTypeHash != SHA256_ENCRYPTED_ENVELOPE
                || keccak256(bytes(evidence.uri)) != keccak256(bytes(uriFor(binding.resourceId)))
        ) revert AVACoreTypes.InvalidState(evidenceId);
        active = resourceActive && policyActive && evidence.status == AVACoreTypes.EvidenceStatus.Active;
    }

    /// @notice Exact binding and current structural eligibility, without package policy authorisation.
    /// @dev Known availability loss returns false; unknown references and technical faults still revert.
    function bindingStatus(uint256 evidenceId) external view returns (Binding memory binding, bool usable) {
        bool active;
        (binding, active) = _bindingContext(evidenceId);
        usable = _isUsable(binding, active);
    }

    function requireUsableBinding(uint256 evidenceId) external view returns (Binding memory binding) {
        bool active;
        (binding, active) = _bindingContext(evidenceId);
        if (!_isUsable(binding, active)) revert AVACoreTypes.EvidenceUnavailable(evidenceId);
    }

    function getBinding(uint256 evidenceId) external view returns (Binding memory) {
        return requireBinding(evidenceId);
    }

    /// @notice Fixed-size gateway context; never recurses into Core's policy-aware usability check.
    function resourceBinding(bytes32 resourceId)
        external
        view
        returns (uint256 evidenceId, bytes32 workflowKey, uint256 packageId, uint256 disclosurePolicyId, bool usable)
    {
        evidenceId = evidenceByResource[resourceId];
        if (evidenceId == 0) return (0, bytes32(0), 0, 0, false);
        (Binding memory binding, bool active) = _bindingContext(evidenceId);
        return
            (evidenceId, binding.workflowKey, binding.packageId, binding.disclosurePolicyId, _isUsable(binding, active));
    }

    function uriFor(bytes32 resourceId) public pure returns (string memory) {
        bytes memory hexadecimal = new bytes(64);
        bytes16 alphabet = "0123456789abcdef";
        for (uint256 i; i < 32; ++i) {
            hexadecimal[2 * i] = alphabet[uint8(resourceId[i]) >> 4];
            hexadecimal[2 * i + 1] = alphabet[uint8(resourceId[i]) & 15];
        }
        return string.concat("ava-private:v1:", string(hexadecimal));
    }

    function _isUsable(Binding memory binding, bool active) private view returns (bool) {
        if (
            !active || !EVIDENCE_REGISTRY.IDENTITY_REGISTRY().getSubjectContext(binding.subjectId).active
                || !EVIDENCE_REGISTRY.DISCLOSURE_REGISTRY().getPolicyReference(binding.disclosurePolicyId).active
        ) return false;
        EVIDENCE_REGISTRY.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(binding.packageId);
        return true;
    }
}
