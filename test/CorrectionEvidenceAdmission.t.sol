// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAWorkflowPolicyRouter} from "../src/core/AVAWorkflowPolicyRouter.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {
    IAVAAuthorityPolicyModule,
    IAVAEvidencePolicyModule,
    IAVADisclosurePolicyModule
} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {AVAAllocationRecordExtension} from "../src/extensions/downstream/AVADownstreamRecordExtensions.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

error AdmissionPolicyVeto(bytes32 capability, uint256 packageId);

interface AdmissionRevertVm {
    function expectRevert(bytes calldata revertData) external;
}

contract CorrectionAdmissionVetoPolicy is
    IAVAAuthorityPolicyModule,
    IAVAEvidencePolicyModule,
    IAVADisclosurePolicyModule,
    RuleModuleIdentity
{
    bytes32 private immutable capability;

    constructor(bytes32 capability_) {
        capability = capability_;
    }

    function validateAuthority(AuthorityContext calldata context) external view {
        if (capability == AVACapabilityKeys.AUTHORITY_POLICY) {
            revert AdmissionPolicyVeto(capability, context.packageId);
        }
    }

    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata context) external view {
        if (capability == AVACapabilityKeys.EVIDENCE_POLICY) {
            revert AdmissionPolicyVeto(capability, context.packageId);
        }
    }

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata) external pure {}

    function validateDisclosure(DisclosureContext calldata context) external view {
        if (capability == AVACapabilityKeys.DISCLOSURE_POLICY) {
            revert AdmissionPolicyVeto(capability, context.packageId);
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return capability;
    }
}

contract ExactCorrectionAdmissionAuthorityPolicy is IAVAAuthorityPolicyModule, RuleModuleIdentity {
    bytes32 private immutable expectedAction;
    bytes32 private immutable expectedHash;

    constructor(bytes32 action, bytes32 decisionHash) {
        expectedAction = action;
        expectedHash = decisionHash;
    }

    function validateAuthority(AuthorityContext calldata context) external view {
        require(context.actionKey == expectedAction, "wrong admission authority action");
        require(context.decisionHash == expectedHash, "wrong admission decision hash");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(expectedAction, expectedHash));
    }
}

/// @notice Admission and consumption use only deployed public Core/extension APIs.
contract CorrectionEvidenceAdmissionTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("correction.admission.test.app");
    bytes32 private constant OTHER_APP = keccak256("correction.admission.other.app");
    bytes32 private constant REASON = keccak256("correction.admission.reason");
    M14PermissiveApplicationModule private application;

    function setUp() public {
        application = new M14PermissiveApplicationModule(APP);
        _setUpRequestAllocation(APP, application, keccak256("correction.admission.object"));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
    }

    function testAdmissionRetainsHistoricalReceiptAndExactDecisionProvenance() public {
        uint256 historical = requestPackageId;
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        uint256 expectedAdmission = packageRegistry.nextPackageId();
        bytes32 action = evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE();
        require(action != AVACoreTypes.ACTION_REGISTER_EVIDENCE, "permission aliases ordinary registration");
        bytes32 expectedHash =
            keccak256(abi.encode(action, block.chainid, address(evidenceRegistry), input, expectedAdmission, REASON));
        uint256 admission = _upgrade(
            AVACapabilityKeys.AUTHORITY_POLICY,
            address(new ExactCorrectionAdmissionAuthorityPolicy(action, expectedHash))
        );
        require(admission == expectedAdmission, "unexpected package id");
        uint256 id = _admit(input, admission);
        AVACoreTypes.EvidenceRecord memory receipt = evidenceRegistry.getEvidence(id);
        require(receipt.packageId == historical && receipt.appId == APP, "historical identity changed");
        require(receipt.workflowKey == REQUEST_WORKFLOW && receipt.subjectId == input.subjectId, "context changed");
        require(
            receipt.commitment == input.commitment && receipt.evidenceTypeHash == input.evidenceTypeHash,
            "evidence changed"
        );
        require(receipt.disclosurePolicyId == input.disclosurePolicyId, "disclosure changed");
        require(
            receipt.registeredBy == SOURCE_ACTOR && receipt.status == AVACoreTypes.EvidenceStatus.Active,
            "registrar or status"
        );
        require(keccak256(bytes(receipt.uri)) == keccak256(bytes(input.uri)), "uri changed");
        (uint256 storedAdmission, bytes32 storedReason, bytes32 storedHash) =
            evidenceRegistry.correctionEvidenceAdmissions(id);
        require(
            storedAdmission == admission && storedReason == REASON && storedHash == expectedHash, "admission provenance"
        );
        require(evidenceRegistry.isCorrectionEvidence(id), "correction marker absent");
        _assertCorrectionUsable(id, historical);
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, historical);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        evidenceRegistry.registerEvidence(input);
    }

    function testAdmissionRequiresBothOrdinaryAndSpecialPermission() public {
        uint256 historical = requestPackageId;
        uint256 admission = _upgrade(bytes32(0), address(0));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _expectAdmissionRevert(input, admission);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), false);
        _expectAdmissionRevert(input, admission);
        require(evidenceRegistry.nextEvidenceId() == 1, "unauthorised admission persisted");
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        require(_admit(input, admission) == 1, "restored permissions did not admit");
    }

    function testAdmissionRequiresActiveEvidenceSubjectAndActor() public {
        uint256 historical = requestPackageId;
        uint256 admission = _upgrade(bytes32(0), address(0));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        input.subjectId = _authority(ROLE_VERIFIER);
        identityRegistry.deactivateSubject(input.subjectId);
        _expectAdmissionRevert(input, admission);
        input.subjectId = _authority(ROLE_SOURCE);
        identityRegistry.deactivateSubject(input.subjectId);
        _expectAdmissionRevert(input, admission);
        require(evidenceRegistry.nextEvidenceId() == 1, "inactive identity admitted");
    }

    function testUnknownAndForeignDisclosureCannotBeAdmitted() public {
        uint256 historical = requestPackageId;
        uint256 admission = _upgrade(bytes32(0), address(0));
        (, uint256 foreignDisclosure) = _foreignPackageAndDisclosure();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        input.disclosurePolicyId = type(uint256).max;
        _expectAdmissionRevert(input, admission);
        input.disclosurePolicyId = foreignDisclosure;
        _expectAdmissionRevert(input, admission);
        input.disclosurePolicyId = requestPolicyId;
        _assertCorrectionUsable(_admit(input, admission), historical);
    }

    function testAdmissionRejectsWrongApplicationAndWorkflowPackages() public {
        uint256 historical = requestPackageId;
        uint256 admission = _upgrade(bytes32(0), address(0));
        (uint256 foreignPackage,) = _foreignPackageAndDisclosure();
        uint256 otherWorkflowPackage = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                keccak256("other.workflow"),
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("request.compatibility"),
                "test:other-workflow"
            ),
            _coreBindings(application)
        );
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        _expectAdmissionRevert(input, foreignPackage);
        _expectAdmissionRevert(input, otherWorkflowPackage);
        input.packageId = foreignPackage;
        _expectAdmissionRevert(input, admission);
        input.packageId = otherWorkflowPackage;
        _expectAdmissionRevert(input, admission);
    }

    function testSameUnknownAndStalePackageReferencesCannotAdmit() public {
        uint256 historical = requestPackageId;
        uint256 admission = _upgrade(bytes32(0), address(0));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(admission);
        _expectAdmissionRevert(input, admission);
        input.packageId = type(uint256).max;
        _expectAdmissionRevert(input, admission);
        input.packageId = historical;
        _expectAdmissionRevert(input, type(uint256).max);
        uint256 current = _upgrade(bytes32(0), address(0));
        _expectAdmissionRevert(input, admission);
        _assertCorrectionUsable(_admit(input, current), historical);
    }

    function testAuthorityPolicyCanVetoActiveAndHistoricalAdmission() public {
        _assertBothPackagePolicyVetoes(AVACapabilityKeys.AUTHORITY_POLICY);
    }

    function testEvidencePolicyCanVetoActiveAndHistoricalAdmission() public {
        _assertBothPackagePolicyVetoes(AVACapabilityKeys.EVIDENCE_POLICY);
    }

    function testDisclosurePolicyCanVetoActiveAndHistoricalAdmission() public {
        _assertBothPackagePolicyVetoes(AVACapabilityKeys.DISCLOSURE_POLICY);
    }

    function testCorrectionReaderAcceptsOrdinaryButRejectsRevokedAndExpiredEvidence() public {
        uint256 historical = requestPackageId;
        uint256 ordinary = _ordinary(historical);
        require(!evidenceRegistry.isCorrectionEvidence(ordinary), "ordinary evidence marked");
        _assertCorrectionUsable(ordinary, historical);
        uint256 admission = _upgrade(bytes32(0), address(0));
        for (uint256 i; i < 2; ++i) {
            uint256 id = _admit(_input(historical), admission);
            _lifecycle(
                id, i == 0 ? AVACoreTypes.EvidenceLifecycleKind.Revoke : AVACoreTypes.EvidenceLifecycleKind.Expire, 0
            );
            require(evidenceRegistry.isCorrectionEvidence(id), "terminal lifecycle erased marker");
            requestVm.expectRevert();
            evidenceRegistry.requireUsableCorrectionEvidenceReferenceForPackage(id, historical);
            require(evidenceRegistry.getEvidenceReference(id).packageId == historical, "lifecycle rewrote package");
        }
        requestVm.expectRevert();
        evidenceRegistry.requireUsableCorrectionEvidenceReferenceForPackage(ordinary, admission);
    }

    function testReplacementPointersDoNotFollowOrLaunderCorrectionMarkers() public {
        uint256 historical = requestPackageId;
        uint256 filing = _ordinary(historical);
        uint256 ordinaryReplacement = _ordinary(historical);
        uint256 admission = _upgrade(bytes32(0), address(0));
        uint256 marked = _admit(_input(historical), admission);
        _lifecycle(filing, AVACoreTypes.EvidenceLifecycleKind.Supersede, marked);
        require(evidenceRegistry.getEvidence(filing).replacementEvidenceId == marked, "replacement not retained");
        requestVm.expectRevert();
        evidenceRegistry.requireUsableCorrectionEvidenceReferenceForPackage(filing, historical);
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(marked, historical);
        _assertCorrectionUsable(marked, historical);
        _lifecycle(marked, AVACoreTypes.EvidenceLifecycleKind.Supersede, ordinaryReplacement);
        require(evidenceRegistry.isCorrectionEvidence(marked), "supersession erased marker");
        require(!evidenceRegistry.isCorrectionEvidence(ordinaryReplacement), "marker transferred to replacement");
        requestVm.expectRevert();
        evidenceRegistry.requireUsableCorrectionEvidenceReferenceForPackage(marked, historical);
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(marked, historical);
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(ordinaryReplacement, historical);
        (uint256 retainedAdmission, bytes32 retainedReason,) = evidenceRegistry.correctionEvidenceAdmissions(marked);
        require(retainedAdmission == admission && retainedReason == REASON, "supersession erased admission");
    }

    function testOrdinaryAllocationCannotConsumeCorrectionOnlyEvidence() public {
        uint256 stateId = _createStateForCommitment(keccak256("ordinary.allocation.source"));
        uint256 historical = requestPackageId;
        uint256 filing = kernel.getRecognisedStateReference(stateId).evidenceReceiptId;
        AVAAllocationRecordExtension allocations = new AVAAllocationRecordExtension(
            kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry
        );
        AVAAllocationRecordExtension.AllocationInput memory input = AVAAllocationRecordExtension.AllocationInput({
            recognisedStateId: stateId,
            roleKey: ROLE_ALLOCATOR,
            authorityId: _authority(ROLE_ALLOCATOR),
            subjectId: _authority(ROLE_SOURCE),
            evidenceId: filing,
            allocationKindKey: keccak256("allocation.kind"),
            units: 1,
            reasonHash: REASON,
            uri: "test:allocation"
        });
        uint256 admission = _upgrade(bytes32(0), address(0));
        requestVm.prank(ALLOCATOR_ACTOR);
        require(allocations.recordAllocation(input) == 1, "ordinary historical allocation failed");
        input.evidenceId = _admit(_input(historical), admission);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        allocations.recordAllocation(input);
        require(allocations.nextAllocationId() == 2, "correction evidence reached ordinary allocation");
    }

    function testFormationPolicyRejectsCorrectionOnlyOriginalEvidence() public {
        uint256 stateId = _createStateForCommitment(keccak256("ordinary.formation.source"));
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(stateId);
        AVAWorkflowPolicyRouter.FormationPolicyInput memory input = AVAWorkflowPolicyRouter.FormationPolicyInput({
            context: IAVAApplicationModule.RecognisedStateFormationContext({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: state.packageId,
                roleKey: ROLE_VERIFIER,
                governedObjectId: state.governedObjectId,
                objectTypeKey: requestObjectTypeKey,
                subjectId: state.subjectId,
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                authorityId: _authority(ROLE_VERIFIER),
                actor: VERIFIER_ACTOR
            }),
            evidenceId: state.evidenceReceiptId,
            disclosurePolicyId: requestPolicyId,
            reasonHash: REASON
        });
        uint256 admission = _upgrade(bytes32(0), address(0));
        AVAWorkflowPolicyRouter router = kernel.POLICY_ROUTER();
        router.validateFormation(input);
        input.evidenceId = _admit(_input(state.packageId), admission);
        AdmissionRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, input.evidenceId));
        router.validateFormation(input);
    }

    function _input(uint256 historical) private view returns (AVAEvidenceRegistry.EvidenceRegistrationInput memory) {
        return AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: historical,
            roleKey: ROLE_SOURCE,
            subjectId: _authority(ROLE_SOURCE),
            commitment: keccak256(abi.encode("admission.evidence", evidenceRegistry.nextEvidenceId())),
            evidenceTypeHash: keccak256("admission.support"),
            disclosurePolicyId: requestPolicyId,
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:admission-evidence"
        });
    }

    function _ordinary(uint256 packageId) private returns (uint256) {
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(packageId);
        requestVm.prank(SOURCE_ACTOR);
        return evidenceRegistry.registerEvidence(input);
    }

    function _admit(AVAEvidenceRegistry.EvidenceRegistrationInput memory input, uint256 admission)
        private
        returns (uint256)
    {
        requestVm.prank(SOURCE_ACTOR);
        return evidenceRegistry.registerCorrectionEvidence(input, admission, REASON);
    }

    function _expectAdmissionRevert(AVAEvidenceRegistry.EvidenceRegistrationInput memory input, uint256 admission)
        private
    {
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        evidenceRegistry.registerCorrectionEvidence(input, admission, REASON);
    }

    function _assertCorrectionUsable(uint256 id, uint256 historical) private view {
        (bytes32 appId, bytes32 workflow, uint256 packageId, bytes32 subject, uint256 disclosure) =
            evidenceRegistry.requireUsableCorrectionEvidenceReferenceForPackage(id, historical);
        require(appId == APP && workflow == REQUEST_WORKFLOW && packageId == historical, "reader package context");
        require(subject == _authority(ROLE_SOURCE) && disclosure == requestPolicyId, "reader identity context");
    }

    function _upgrade(bytes32 capability, address policy) private returns (uint256) {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        for (uint256 i; i < bindings.length; ++i) {
            if (bindings[i].capabilityKey == capability) bindings[i] = _coreBinding(capability, policy);
        }
        uint64 nextVersion = packageRegistry.getRulePackageById(requestPackageId).version + 1;
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                nextVersion,
                keccak256("request.compatibility"),
                "test:admission-upgrade"
            ),
            requestPackageId,
            bindings
        );
        return requestPackageId;
    }

    function _assertBothPackagePolicyVetoes(bytes32 capability) private {
        uint256 historical = requestPackageId;
        uint256 vetoPackage = _upgrade(capability, address(new CorrectionAdmissionVetoPolicy(capability)));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input(historical);
        requestVm.prank(SOURCE_ACTOR);
        AdmissionRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AdmissionPolicyVeto.selector, capability, vetoPackage));
        evidenceRegistry.registerCorrectionEvidence(input, vetoPackage, REASON);
        uint256 active = _upgrade(bytes32(0), address(0));
        input.packageId = vetoPackage;
        requestVm.prank(SOURCE_ACTOR);
        AdmissionRevertVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AdmissionPolicyVeto.selector, capability, vetoPackage));
        evidenceRegistry.registerCorrectionEvidence(input, active, REASON);
        input.packageId = historical;
        _assertCorrectionUsable(_admit(input, active), historical);
    }

    function _lifecycle(uint256 id, AVACoreTypes.EvidenceLifecycleKind kind, uint256 replacement) private {
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            id, ROLE_SOURCE, _authority(ROLE_SOURCE), kind, replacement, REASON, "test:admission-lifecycle"
        );
    }

    function _foreignPackageAndDisclosure() private returns (uint256 packageId, uint256 disclosureId) {
        applicationRegistry.registerApplication(
            OTHER_APP, keccak256("other.app"), keccak256("other.authority"), address(this), "test:other"
        );
        bytes32 registrar = keccak256(abi.encode(OTHER_APP, ROLE_PACKAGE));
        bytes32 source = keccak256(abi.encode(OTHER_APP, ROLE_SOURCE));
        identityRegistry.assignSubject(address(this), OTHER_APP, ROLE_PACKAGE, registrar, "test:other-package");
        identityRegistry.assignSubject(SOURCE_ACTOR, OTHER_APP, ROLE_SOURCE, source, "test:other-source");
        authorityMatrix.setPermission(OTHER_APP, ROLE_PACKAGE, AVACoreTypes.ACTION_REGISTER_RULE_PACKAGE, true);
        authorityMatrix.setPermission(OTHER_APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_DISCLOSURE_POLICY, true);
        packageId = packageRegistry.registerRulePackage(
            _corePackageInput(
                OTHER_APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                registrar,
                1,
                keccak256("request.compatibility"),
                "test:other-package"
            ),
            _coreBindings(new M14PermissiveApplicationModule(OTHER_APP))
        );
        requestVm.prank(SOURCE_ACTOR);
        disclosureId = disclosureRegistry.registerPolicy(
            OTHER_APP, ROLE_SOURCE, source, keccak256("other.disclosure"), "Other", "test:other-disclosure"
        );
    }
}
