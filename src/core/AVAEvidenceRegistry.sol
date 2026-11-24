// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IAVAApplicationModule} from "../interfaces/IAVAApplicationModule.sol";
import {AVAAuthorityMatrix} from "./AVAAuthorityMatrix.sol";
import {AVACapabilityKeys} from "./AVACapabilityKeys.sol";
import {AVACoreTypes} from "./AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "./AVACoreRulePackageRegistry.sol";
import {AVADisclosurePolicyRegistry} from "./AVADisclosurePolicyRegistry.sol";
import {AVAIdentityRegistry} from "./AVAIdentityRegistry.sol";
import {IAVACorrectionReview} from "./interfaces/IAVACorrectionReview.sol";
import {
    IAVAEvidencePolicyModule,
    IAVAEvidenceLifecycleModule,
    IAVADisclosurePolicyModule,
    IAVAAuthorityPolicyModule
} from "./interfaces/IAVACoreRuleModules.sol";

contract AVAEvidenceRegistry {
    bytes32 public constant ACTION_REGISTER_CORRECTION_EVIDENCE = keccak256("ava.core.register-correction-evidence.v1");
    bytes32 public constant ACTION_REQUIRE_USABLE_EVIDENCE = keccak256("ava.core.require-usable-evidence.v1");

    struct CorrectionEvidenceAdmission {
        uint256 admissionPackageId;
        bytes32 reasonHash;
        bytes32 decisionHash;
    }

    struct EvidenceRegistrationInput {
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        bytes32 roleKey;
        bytes32 subjectId;
        bytes32 commitment;
        bytes32 evidenceTypeHash;
        uint256 disclosurePolicyId;
        bytes32 authorityId;
        string uri;
    }

    struct EvidenceRegistrationModules {
        AVACoreRulePackageRegistry.VerifiedPackageContext rulePackage;
        IAVAApplicationModule application;
        IAVAEvidencePolicyModule evidencePolicy;
        IAVADisclosurePolicyModule disclosurePolicy;
        IAVAAuthorityPolicyModule authorityPolicy;
    }

    /// @notice Fixed-size evidence context for contract-to-contract validation paths.
    /// @dev Full metadata, including URI and registrar, remains available through getEvidence.
    struct EvidenceReference {
        uint256 id;
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        bytes32 commitment;
        bytes32 evidenceTypeHash;
        bytes32 subjectId;
        uint256 disclosurePolicyId;
        bytes32 authorityId;
        AVACoreTypes.EvidenceStatus status;
        uint256 lastLifecycleRecordId;
        uint256 replacementEvidenceId;
    }

    AVAAuthorityMatrix public immutable AUTHORITY_MATRIX;
    AVAIdentityRegistry public immutable IDENTITY_REGISTRY;
    AVACoreRulePackageRegistry public immutable RULE_PACKAGE_REGISTRY;
    AVADisclosurePolicyRegistry public immutable DISCLOSURE_REGISTRY;

    mapping(uint256 => AVACoreTypes.EvidenceRecord) private evidenceRecords;
    mapping(uint256 => AVACoreTypes.EvidenceLifecycleRecord) private lifecycleRecords;
    mapping(uint256 => CorrectionEvidenceAdmission) public correctionEvidenceAdmissions;
    mapping(uint256 => address) public reviewEvidenceRegistryById;
    mapping(uint256 => uint256) public reviewEvidenceCaseIdById;
    uint256 public nextEvidenceId = 1;
    uint256 public nextLifecycleRecordId = 1;

    event EvidenceRegistered(
        uint256 indexed evidenceId,
        bytes32 indexed appId,
        uint256 indexed packageId,
        bytes32 subjectId,
        bytes32 commitment,
        bytes32 evidenceTypeHash,
        address registeredBy
    );
    event EvidenceLifecycleRecorded(
        uint256 indexed lifecycleRecordId,
        uint256 indexed evidenceId,
        AVACoreTypes.EvidenceLifecycleKind indexed kind,
        AVACoreTypes.EvidenceStatus toStatus,
        bytes32 authorityId,
        address createdBy
    );
    event CorrectionEvidenceAdmitted(
        uint256 indexed evidenceId,
        uint256 indexed historicalPackageId,
        uint256 indexed admissionPackageId,
        bytes32 authorityId,
        bytes32 decisionHash
    );

    constructor(
        AVAAuthorityMatrix authorityMatrix_,
        AVAIdentityRegistry identityRegistry_,
        AVACoreRulePackageRegistry rulePackageRegistry_,
        AVADisclosurePolicyRegistry disclosureRegistry_
    ) {
        if (
            address(authorityMatrix_) == address(0) || address(identityRegistry_) == address(0)
                || address(rulePackageRegistry_) == address(0) || address(disclosureRegistry_) == address(0)
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        if (
            address(authorityMatrix_.IDENTITY_REGISTRY()) != address(identityRegistry_)
                || address(authorityMatrix_.APPLICATION_REGISTRY())
                    != address(rulePackageRegistry_.APPLICATION_REGISTRY())
                || address(rulePackageRegistry_.AUTHORITY_MATRIX()) != address(authorityMatrix_)
                || address(disclosureRegistry_.AUTHORITY_MATRIX()) != address(authorityMatrix_)
        ) {
            revert AVACoreTypes.InvalidState(0);
        }
        AUTHORITY_MATRIX = authorityMatrix_;
        IDENTITY_REGISTRY = identityRegistry_;
        RULE_PACKAGE_REGISTRY = rulePackageRegistry_;
        DISCLOSURE_REGISTRY = disclosureRegistry_;
    }

    function registerEvidence(EvidenceRegistrationInput calldata input) external returns (uint256 evidenceId) {
        return _registerEvidence(input);
    }

    /// @notice The caller registers each item under its own authority and policy checks in one transaction.
    function registerEvidencePair(EvidenceRegistrationInput calldata first, EvidenceRegistrationInput calldata second)
        external
        returns (uint256 firstId, uint256 secondId)
    {
        firstId = _registerEvidence(first);
        secondId = _registerEvidence(second);
    }

    function _registerEvidence(EvidenceRegistrationInput calldata input) private returns (uint256 evidenceId) {
        _requireRegistrationAuthority(input);
        EvidenceRegistrationModules memory modules = _verifiedRegistrationModules(input, input.packageId, true);
        _validateRegistrationPolicies(input, modules, AVACoreTypes.ACTION_REGISTER_EVIDENCE);
        return _storeEvidence(input);
    }

    /// @notice Admits new decision support without reopening ordinary historical registration.
    /// @dev Both rule versions approve reception; the receipt can only support correction procedures.
    function registerCorrectionEvidence(
        EvidenceRegistrationInput calldata input,
        uint256 admissionPackageId,
        bytes32 reasonHash
    ) external returns (uint256 evidenceId) {
        _requireRegistrationAuthority(input);
        AUTHORITY_MATRIX.requireAuthorisedSubject(
            msg.sender, input.appId, input.roleKey, ACTION_REGISTER_CORRECTION_EVIDENCE, input.authorityId
        );
        if (reasonHash == bytes32(0) || input.packageId == admissionPackageId) revert AVACoreTypes.EmptyValue();
        EvidenceRegistrationModules memory historical = _verifiedRegistrationModules(input, input.packageId, false);
        EvidenceRegistrationModules memory admission = _verifiedRegistrationModules(input, admissionPackageId, true);
        if (
            historical.rulePackage.version >= admission.rulePackage.version
                || historical.rulePackage.compatibilityKey != admission.rulePackage.compatibilityKey
        ) revert AVACoreTypes.InvalidState(admissionPackageId);
        bytes32 decisionHash = keccak256(
            abi.encode(
                ACTION_REGISTER_CORRECTION_EVIDENCE, block.chainid, address(this), input, admissionPackageId, reasonHash
            )
        );
        _validateRegistrationPolicies(input, historical, ACTION_REGISTER_CORRECTION_EVIDENCE);
        _validateRegistrationPolicies(input, admission, ACTION_REGISTER_CORRECTION_EVIDENCE);
        _validateAdmissionAuthority(input, historical, decisionHash);
        _validateAdmissionAuthority(input, admission, decisionHash);
        evidenceId = _storeEvidence(input);
        correctionEvidenceAdmissions[evidenceId] = CorrectionEvidenceAdmission({
            admissionPackageId: admissionPackageId, reasonHash: reasonHash, decisionHash: decisionHash
        });
        emit CorrectionEvidenceAdmitted(
            evidenceId, input.packageId, admissionPackageId, input.authorityId, decisionHash
        );
    }

    function isCorrectionEvidence(uint256 evidenceId) public view returns (bool) {
        return correctionEvidenceAdmissions[evidenceId].admissionPackageId != 0
            || reviewEvidenceRegistryById[evidenceId] != address(0);
    }

    /// @notice Purpose-bound support for the Core's independent review, including a vetoed historical package.
    /// @dev No ordinary registration, formation, support or correction path may consume this receipt.
    function registerReviewEvidence(
        EvidenceRegistrationInput calldata input,
        IAVACorrectionReview registry,
        uint256 caseId
    ) external returns (uint256 id) {
        (bytes32 appId, bytes32 workflowKey, uint256 packageId) = registry.canRegisterEvidence(
            caseId, msg.sender, input.roleKey, input.authorityId
        );
        AUTHORITY_MATRIX.requireAuthorisedSubject(
            msg.sender, input.appId, input.roleKey, AVACoreTypes.ACTION_REVIEW_CORRECTION, input.authorityId
        );
        if (
            input.appId != appId || input.workflowKey != workflowKey || input.packageId != packageId
                || input.subjectId != input.authorityId || input.commitment == bytes32(0)
                || input.evidenceTypeHash == bytes32(0)
        ) revert AVACoreTypes.InvalidState(caseId);
        // The authorised canonical subject is active in this app, and equals input.subjectId above.
        DISCLOSURE_REGISTRY.requireActivePolicyReference(input.disclosurePolicyId, input.appId);
        id = _storeEvidence(input);
        reviewEvidenceRegistryById[id] = address(registry);
        reviewEvidenceCaseIdById[id] = caseId;
    }

    function _requireRegistrationAuthority(EvidenceRegistrationInput calldata input) private view {
        if (
            input.appId == bytes32(0) || input.workflowKey == bytes32(0) || input.packageId == 0
                || input.roleKey == bytes32(0) || input.subjectId == bytes32(0) || input.commitment == bytes32(0)
                || input.evidenceTypeHash == bytes32(0) || input.disclosurePolicyId == 0
                || input.authorityId == bytes32(0)
        ) {
            revert AVACoreTypes.EmptyValue();
        }
        bytes32 callerAuthorityId = AUTHORITY_MATRIX.requireAuthorisedCanonicalSubject(
            msg.sender, input.appId, input.roleKey, AVACoreTypes.ACTION_REGISTER_EVIDENCE
        );
        if (callerAuthorityId != input.authorityId) {
            revert AVACoreTypes.SubjectMismatch(callerAuthorityId, input.authorityId);
        }
        IDENTITY_REGISTRY.requireActiveSubjectReference(input.subjectId, input.appId);
        DISCLOSURE_REGISTRY.requireActivePolicyReference(input.disclosurePolicyId, input.appId);
    }

    function _validateRegistrationPolicies(
        EvidenceRegistrationInput calldata input,
        EvidenceRegistrationModules memory modules,
        bytes32 actionKey
    ) private view {
        IAVAApplicationModule.EvidenceContext memory context = IAVAApplicationModule.EvidenceContext({
            appId: input.appId,
            workflowKey: input.workflowKey,
            packageId: modules.rulePackage.packageId,
            roleKey: input.roleKey,
            subjectId: input.subjectId,
            evidenceTypeHash: input.evidenceTypeHash,
            disclosurePolicyId: input.disclosurePolicyId,
            authorityId: input.authorityId,
            actor: msg.sender
        });
        modules.application.validateEvidence(context);
        modules.evidencePolicy.validateEvidence(context);
        modules.disclosurePolicy
            .validateDisclosure(
                IAVADisclosurePolicyModule.DisclosureContext({
                    appId: input.appId,
                    workflowKey: input.workflowKey,
                    packageId: modules.rulePackage.packageId,
                    actionKey: actionKey,
                    roleKey: input.roleKey,
                    stage: actionKey == AVACoreTypes.ACTION_REGISTER_EVIDENCE
                        ? AVACoreTypes.Stage.Attribution
                        : AVACoreTypes.Stage.Verification,
                    objectTypeKey: bytes32(0),
                    subjectId: input.subjectId,
                    disclosurePolicyId: input.disclosurePolicyId,
                    targetId: actionKey == AVACoreTypes.ACTION_REGISTER_EVIDENCE ? 0 : input.packageId,
                    evidenceId: 0,
                    evidenceTypeHash: input.evidenceTypeHash,
                    authorityId: input.authorityId,
                    actor: msg.sender
                })
            );
    }

    function _validateAdmissionAuthority(
        EvidenceRegistrationInput calldata input,
        EvidenceRegistrationModules memory modules,
        bytes32 decisionHash
    ) private view {
        modules.authorityPolicy
            .validateAuthority(
                IAVAAuthorityPolicyModule.AuthorityContext({
                    appId: input.appId,
                    workflowKey: input.workflowKey,
                    packageId: modules.rulePackage.packageId,
                    actionKey: ACTION_REGISTER_CORRECTION_EVIDENCE,
                    roleKey: input.roleKey,
                    stage: AVACoreTypes.Stage.Verification,
                    objectTypeKey: bytes32(0),
                    targetId: input.packageId,
                    targetSubjectId: input.subjectId,
                    authorityId: input.authorityId,
                    decisionHash: decisionHash,
                    actor: msg.sender
                })
            );
    }

    function _storeEvidence(EvidenceRegistrationInput calldata input) private returns (uint256 evidenceId) {
        evidenceId = nextEvidenceId++;
        evidenceRecords[evidenceId] = AVACoreTypes.EvidenceRecord({
            id: evidenceId,
            appId: input.appId,
            workflowKey: input.workflowKey,
            packageId: input.packageId,
            commitment: input.commitment,
            evidenceTypeHash: input.evidenceTypeHash,
            subjectId: input.subjectId,
            disclosurePolicyId: input.disclosurePolicyId,
            authorityId: input.authorityId,
            uri: input.uri,
            registeredBy: msg.sender,
            status: AVACoreTypes.EvidenceStatus.Active,
            lastLifecycleRecordId: 0,
            replacementEvidenceId: 0,
            registeredAt: uint64(block.timestamp)
        });
        emit EvidenceRegistered(
            evidenceId,
            input.appId,
            input.packageId,
            input.subjectId,
            input.commitment,
            input.evidenceTypeHash,
            msg.sender
        );
    }

    function _verifiedRegistrationModules(EvidenceRegistrationInput calldata input, uint256 packageId, bool active)
        private
        view
        returns (EvidenceRegistrationModules memory modules)
    {
        bytes32[] memory keys = new bytes32[](4);
        keys[0] = AVACapabilityKeys.APPLICATION;
        keys[1] = AVACapabilityKeys.EVIDENCE_POLICY;
        keys[2] = AVACapabilityKeys.DISCLOSURE_POLICY;
        keys[3] = AVACapabilityKeys.AUTHORITY_POLICY;
        AVACoreRulePackageRegistry.VerifiedPackageContext memory rulePackage;
        address[] memory addresses;
        if (active) {
            (rulePackage, addresses) =
                RULE_PACKAGE_REGISTRY.getActiveVerifiedModulesCompact(input.appId, input.workflowKey, packageId, keys);
        } else {
            (rulePackage, addresses) = RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(packageId, keys);
            if (rulePackage.appId != input.appId || rulePackage.workflowKey != input.workflowKey) {
                revert AVACoreTypes.InvalidState(packageId);
            }
        }
        modules = EvidenceRegistrationModules({
            rulePackage: rulePackage,
            application: IAVAApplicationModule(addresses[0]),
            evidencePolicy: IAVAEvidencePolicyModule(addresses[1]),
            disclosurePolicy: IAVADisclosurePolicyModule(addresses[2]),
            authorityPolicy: IAVAAuthorityPolicyModule(addresses[3])
        });
    }

    function recordEvidenceLifecycle(
        uint256 evidenceId,
        bytes32 roleKey,
        bytes32 authorityId,
        AVACoreTypes.EvidenceLifecycleKind kind,
        uint256 replacementEvidenceId,
        bytes32 reasonHash,
        string calldata uri
    ) external returns (uint256 lifecycleRecordId) {
        AVACoreTypes.EvidenceRecord storage evidence = _evidenceStorage(evidenceId);
        if (
            roleKey == bytes32(0) || authorityId == bytes32(0) || kind == AVACoreTypes.EvidenceLifecycleKind.None
                || reasonHash == bytes32(0) || evidence.status != AVACoreTypes.EvidenceStatus.Active
        ) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
        bytes32 callerAuthorityId = AUTHORITY_MATRIX.requireAuthorisedCanonicalSubject(
            msg.sender, evidence.appId, roleKey, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE
        );
        if (callerAuthorityId != authorityId) {
            revert AVACoreTypes.SubjectMismatch(callerAuthorityId, authorityId);
        }
        AVACoreTypes.EvidenceStatus toStatus = _statusForLifecycleKind(kind);
        if (kind == AVACoreTypes.EvidenceLifecycleKind.Supersede) {
            _requireCompatibleReplacement(evidence, replacementEvidenceId);
        } else if (replacementEvidenceId != 0) {
            revert AVACoreTypes.InvalidState(replacementEvidenceId);
        }
        IAVAEvidenceLifecycleModule(
                RULE_PACKAGE_REGISTRY.getModule(evidence.packageId, AVACapabilityKeys.EVIDENCE_LIFECYCLE)
            )
            .validateEvidenceLifecycle(
                IAVAEvidenceLifecycleModule.EvidenceLifecycleContext({
                    appId: evidence.appId,
                    workflowKey: evidence.workflowKey,
                    packageId: evidence.packageId,
                    evidenceId: evidence.id,
                    evidenceTypeHash: evidence.evidenceTypeHash,
                    subjectId: evidence.subjectId,
                    disclosurePolicyId: evidence.disclosurePolicyId,
                    fromStatus: evidence.status,
                    toStatus: toStatus,
                    kind: kind,
                    replacementEvidenceId: replacementEvidenceId,
                    roleKey: roleKey,
                    authorityId: authorityId,
                    reasonHash: reasonHash,
                    actor: msg.sender
                })
            );

        lifecycleRecordId = nextLifecycleRecordId++;
        lifecycleRecords[lifecycleRecordId] = AVACoreTypes.EvidenceLifecycleRecord({
            id: lifecycleRecordId,
            evidenceId: evidenceId,
            appId: evidence.appId,
            packageId: evidence.packageId,
            kind: kind,
            fromStatus: evidence.status,
            toStatus: toStatus,
            replacementEvidenceId: replacementEvidenceId,
            authorityId: authorityId,
            reasonHash: reasonHash,
            uri: uri,
            createdBy: msg.sender,
            createdAt: uint64(block.timestamp)
        });
        evidence.status = toStatus;
        evidence.lastLifecycleRecordId = lifecycleRecordId;
        evidence.replacementEvidenceId = replacementEvidenceId;
        emit EvidenceLifecycleRecorded(lifecycleRecordId, evidenceId, kind, toStatus, authorityId, msg.sender);
    }

    function getEvidence(uint256 evidenceId) external view returns (AVACoreTypes.EvidenceRecord memory) {
        AVACoreTypes.EvidenceRecord memory evidence = evidenceRecords[evidenceId];
        if (evidence.id == 0) revert AVACoreTypes.UnknownReference(evidenceId);
        return evidence;
    }

    function getEvidenceReference(uint256 evidenceId) external view returns (EvidenceReference memory evidenceRef) {
        AVACoreTypes.EvidenceRecord storage evidence = _evidenceStorage(evidenceId);
        evidenceRef = EvidenceReference({
            id: evidence.id,
            appId: evidence.appId,
            workflowKey: evidence.workflowKey,
            packageId: evidence.packageId,
            commitment: evidence.commitment,
            evidenceTypeHash: evidence.evidenceTypeHash,
            subjectId: evidence.subjectId,
            disclosurePolicyId: evidence.disclosurePolicyId,
            authorityId: evidence.authorityId,
            status: evidence.status,
            lastLifecycleRecordId: evidence.lastLifecycleRecordId,
            replacementEvidenceId: evidence.replacementEvidenceId
        });
    }

    function getEvidenceLifecycleRecord(uint256 lifecycleRecordId)
        external
        view
        returns (AVACoreTypes.EvidenceLifecycleRecord memory)
    {
        AVACoreTypes.EvidenceLifecycleRecord memory record = lifecycleRecords[lifecycleRecordId];
        if (record.id == 0) revert AVACoreTypes.UnknownReference(lifecycleRecordId);
        return record;
    }

    function requireUsableEvidenceReferenceForPackage(uint256 evidenceId, uint256 packageId)
        external
        view
        returns (
            bytes32 appId,
            bytes32 workflowKey,
            uint256 receiptPackageId,
            bytes32 subjectId,
            uint256 disclosurePolicyId
        )
    {
        AVACoreTypes.EvidenceRecord storage evidence = _usableEvidence(evidenceId, packageId);
        if (isCorrectionEvidence(evidenceId)) revert AVACoreTypes.InvalidState(evidenceId);
        return
            (evidence.appId, evidence.workflowKey, evidence.packageId, evidence.subjectId, evidence.disclosurePolicyId);
    }

    function requireUsableCorrectionEvidenceReferenceForPackage(uint256 evidenceId, uint256 packageId)
        external
        view
        returns (bytes32, bytes32, uint256, bytes32, uint256)
    {
        AVACoreTypes.EvidenceRecord storage evidence = _usableEvidence(evidenceId, packageId);
        if (reviewEvidenceRegistryById[evidenceId] != address(0)) revert AVACoreTypes.InvalidState(evidenceId);
        DISCLOSURE_REGISTRY.requireActivePolicyReference(evidence.disclosurePolicyId, evidence.appId);
        return
            (evidence.appId, evidence.workflowKey, evidence.packageId, evidence.subjectId, evidence.disclosurePolicyId);
    }

    /// @notice Exact historical correction support, with scope, purpose and current subject checks together.
    function requireCorrectionSupport(uint256 evidenceId, uint256 packageId, bytes32 appId, bytes32 workflowKey)
        external
        view
        returns (bytes32 subjectId)
    {
        AVACoreTypes.EvidenceRecord storage evidence = _usableEvidence(evidenceId, packageId);
        if (
            reviewEvidenceRegistryById[evidenceId] != address(0) || evidence.appId != appId
                || evidence.workflowKey != workflowKey
        ) revert AVACoreTypes.InvalidState(evidenceId);
        DISCLOSURE_REGISTRY.requireActivePolicyReference(evidence.disclosurePolicyId, appId);
        IDENTITY_REGISTRY.requireActiveSubjectReference(evidence.subjectId, appId);
        return evidence.subjectId;
    }

    /// @notice Current eligibility, not support authorisation or a file-retrieval guarantee.
    /// @dev A known unavailable basis returns false. Invalid references, broken package identities
    /// and policy failures still revert. Purpose restrictions remain with the consuming interface.
    function isEvidenceAvailableForPackage(uint256 evidenceId, uint256 packageId) external view returns (bool) {
        AVACoreTypes.EvidenceRecord storage evidence = evidenceRecords[evidenceId];
        if (evidence.id == 0 || packageId == 0 || evidence.packageId != packageId) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
        // Verify the complete package outside the catch; availability never masks identity drift.
        IAVAEvidencePolicyModule policy =
            IAVAEvidencePolicyModule(RULE_PACKAGE_REGISTRY.getModule(packageId, AVACapabilityKeys.EVIDENCE_POLICY));
        if (
            evidence.status != AVACoreTypes.EvidenceStatus.Active
                || !IDENTITY_REGISTRY.getSubjectContext(evidence.subjectId).active
        ) return false;
        try policy.validateEvidenceUse(_currentUseContext(evidence)) {
            return true;
        } catch (bytes memory revertData) {
            if (_isEvidenceUnavailableFor(revertData, evidenceId)) return false;
            assembly ("memory-safe") {
                revert(add(revertData, 32), mload(revertData))
            }
        }
    }

    function _isEvidenceUnavailableFor(bytes memory revertData, uint256 evidenceId) private pure returns (bool) {
        return keccak256(revertData)
            == keccak256(abi.encodeWithSelector(AVACoreTypes.EvidenceUnavailable.selector, evidenceId));
    }

    function _usableEvidence(uint256 evidenceId, uint256 packageId)
        private
        view
        returns (AVACoreTypes.EvidenceRecord storage evidence)
    {
        evidence = evidenceRecords[evidenceId];
        if (
            evidence.id == 0 || packageId == 0 || evidence.packageId != packageId
                || evidence.status != AVACoreTypes.EvidenceStatus.Active
        ) revert AVACoreTypes.InvalidState(evidenceId);
        IAVAEvidencePolicyModule(RULE_PACKAGE_REGISTRY.getModule(packageId, AVACapabilityKeys.EVIDENCE_POLICY))
            .validateEvidenceUse(_currentUseContext(evidence));
    }

    function _currentUseContext(AVACoreTypes.EvidenceRecord storage evidence)
        private
        view
        returns (IAVAApplicationModule.EvidenceUseContext memory)
    {
        return IAVAApplicationModule.EvidenceUseContext({
            appId: evidence.appId,
            workflowKey: evidence.workflowKey,
            packageId: evidence.packageId,
            actionKey: ACTION_REQUIRE_USABLE_EVIDENCE,
            roleKey: bytes32(0),
            stage: AVACoreTypes.Stage.None,
            targetId: 0,
            objectTypeKey: bytes32(0),
            subjectId: evidence.subjectId,
            evidenceId: evidence.id,
            evidenceTypeHash: evidence.evidenceTypeHash,
            disclosurePolicyId: evidence.disclosurePolicyId,
            evidenceStatus: evidence.status,
            authorityId: bytes32(0),
            actor: address(0)
        });
    }

    function requireEvidenceReferenceForPackage(uint256 evidenceId, uint256 packageId)
        external
        view
        returns (
            bytes32 appId,
            bytes32 workflowKey,
            uint256 receiptPackageId,
            bytes32 subjectId,
            uint256 disclosurePolicyId
        )
    {
        AVACoreTypes.EvidenceRecord storage evidence = evidenceRecords[evidenceId];
        if (evidence.id == 0 || packageId == 0 || evidence.packageId != packageId) {
            revert AVACoreTypes.InvalidState(evidenceId);
        }
        return
            (evidence.appId, evidence.workflowKey, evidence.packageId, evidence.subjectId, evidence.disclosurePolicyId);
    }

    function _evidenceStorage(uint256 evidenceId) internal view returns (AVACoreTypes.EvidenceRecord storage evidence) {
        evidence = evidenceRecords[evidenceId];
        if (evidence.id == 0) revert AVACoreTypes.UnknownReference(evidenceId);
    }

    function _requireCompatibleReplacement(AVACoreTypes.EvidenceRecord storage evidence, uint256 replacementEvidenceId)
        internal
        view
    {
        if (replacementEvidenceId == evidence.id) revert AVACoreTypes.InvalidState(replacementEvidenceId);
        AVACoreTypes.EvidenceRecord memory replacement = evidenceRecords[replacementEvidenceId];
        if (
            replacement.id == 0 || replacement.status != AVACoreTypes.EvidenceStatus.Active
                || replacement.packageId != evidence.packageId || replacement.appId != evidence.appId
                || replacement.subjectId != evidence.subjectId
                || replacement.disclosurePolicyId != evidence.disclosurePolicyId
                || replacement.evidenceTypeHash != evidence.evidenceTypeHash
        ) {
            revert AVACoreTypes.InvalidState(replacementEvidenceId);
        }
    }

    function _statusForLifecycleKind(AVACoreTypes.EvidenceLifecycleKind kind)
        internal
        pure
        returns (AVACoreTypes.EvidenceStatus)
    {
        if (kind == AVACoreTypes.EvidenceLifecycleKind.Revoke) return AVACoreTypes.EvidenceStatus.Revoked;
        if (kind == AVACoreTypes.EvidenceLifecycleKind.Expire) return AVACoreTypes.EvidenceStatus.Expired;
        if (kind == AVACoreTypes.EvidenceLifecycleKind.Supersede) return AVACoreTypes.EvidenceStatus.Superseded;
        revert AVACoreTypes.EmptyValue();
    }
}
