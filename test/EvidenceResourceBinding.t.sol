// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVAEvidencePolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";
import {AVAPrivacyRegistry} from "../src/extensions/privacy/AVAPrivacyRegistry.sol";
import {AVAEvidenceResourceBinding} from "../src/extensions/privacy/AVAEvidenceResourceBinding.sol";
import {AVABoundConfidentialEvidencePolicy} from "../src/extensions/privacy/AVABoundConfidentialEvidencePolicy.sol";

interface EvidenceBindingVm {
    function expectRevert(bytes calldata revertData) external;
}

contract RejectCurrentUseEvidencePolicy is IAVAEvidencePolicyModule, RuleModuleIdentity {
    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) external pure {
        revert AVACoreTypes.InvalidState(context.evidenceId);
    }
}

contract MismatchedUnavailableEvidencePolicy is IAVAEvidencePolicyModule, RuleModuleIdentity {
    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) external pure {
        revert AVACoreTypes.EvidenceUnavailable(context.evidenceId + 1);
    }
}

contract EvidenceResourceBindingTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("evidence.binding.app");
    bytes32 private constant ENVELOPE = keccak256("sha256.encrypted-envelope.v1");
    bytes32 private constant DIGEST = 0x031edd7d41651593c5fe5c14c8cfb7eaa12d3cae58b1d5c1d9e1856e58b20dca;
    bytes32 private constant RESOURCE = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 private constant SECOND_RESOURCE = 0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 private constant CASE_ID = keccak256("evidence.binding.case");
    bytes32 private constant MATERIAL = keccak256("evidence.binding.material");
    string private constant RESOURCE_URI =
        "ava-private:v1:1111111111111111111111111111111111111111111111111111111111111111";
    string private constant SECOND_RESOURCE_URI =
        "ava-private:v1:2222222222222222222222222222222222222222222222222222222222222222";
    M14PermissiveApplicationModule private application;
    AVAPrivacyRegistry private privacy;
    AVAEvidenceResourceBinding private bindings;
    AVABoundConfidentialEvidencePolicy private boundPolicy;
    uint256 private privacyPolicyId;

    function setUp() public {
        application = new M14PermissiveApplicationModule(APP);
        _setUpRequestAllocation(APP, application, keccak256("evidence.binding.object"));
    }

    event log_named_uint(string key, uint256 value);

    /// @notice Compare warm public availability calls with short and long subject metadata.
    function testEvidenceAvailabilitySubjectMetadataCost() public {
        uint256 shortId = _register(_input());
        bytes32 longRole = keccak256("evidence.binding.long-subject.role");
        bytes32 longSubject = keccak256("evidence.binding.long-subject");
        identityRegistry.assignSubject(SOURCE_ACTOR, APP, longRole, longSubject, string(new bytes(4096)));
        authorityMatrix.setPermission(APP, longRole, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.roleKey = longRole;
        input.subjectId = longSubject;
        input.authorityId = longSubject;
        uint256 longId = _register(input);

        require(evidenceRegistry.isEvidenceAvailableForPackage(shortId, requestPackageId));
        require(evidenceRegistry.isEvidenceAvailableForPackage(longId, requestPackageId));
        uint256 beforeGas = gasleft();
        bool shortAvailable = evidenceRegistry.isEvidenceAvailableForPackage(shortId, requestPackageId);
        uint256 shortGas = beforeGas - gasleft();
        beforeGas = gasleft();
        bool longAvailable = evidenceRegistry.isEvidenceAvailableForPackage(longId, requestPackageId);
        uint256 longGas = beforeGas - gasleft();
        require(shortAvailable && longAvailable, "metadata changed availability");
        emit log_named_uint("short subject availability warm public call gas", shortGas);
        emit log_named_uint("4KiB subject availability warm public call gas", longGas);
    }

    /// @notice Compare with the existing short-policy usable-binding diagnostic.
    function testUsableBindingLongPolicyMetadataCost() public {
        string memory metadata = string(new bytes(4096));
        requestVm.prank(SOURCE_ACTOR);
        requestPolicyId = disclosureRegistry.registerPolicy(
            APP, ROLE_SOURCE, _authority(ROLE_SOURCE), keccak256("long.disclosure"), metadata, metadata
        );
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        bindings.requireUsableBinding(id);
        uint256 beforeGas = gasleft();
        AVAEvidenceResourceBinding.Binding memory result = bindings.requireUsableBinding(id);
        uint256 used = beforeGas - gasleft();
        require(result.resourceId == RESOURCE && result.disclosurePolicyId == requestPolicyId, "wrong binding");
        emit log_named_uint("4KiB policy usable binding warm public call gas", used);
    }

    function testEvidencePairUsesCallerForBothItemsAndRollsBackIfSecondIsInvalid() public {
        _boundSetup();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory first = _input();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory second = _input();
        second.roleKey = bytes32(0);
        uint256 expectedFirst = evidenceRegistry.nextEvidenceId();
        requestVm.expectRevert();
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.registerEvidencePair(first, second);
        assert(evidenceRegistry.nextEvidenceId() == expectedFirst);

        second.roleKey = first.roleKey;
        second.uri = SECOND_RESOURCE_URI;
        second.commitment = keccak256("second encrypted evidence");
        requestVm.prank(SOURCE_ACTOR);
        (uint256 firstId, uint256 secondId) = evidenceRegistry.registerEvidencePair(first, second);
        assert(firstId == expectedFirst && secondId == expectedFirst + 1);
        AVACoreTypes.EvidenceRecord memory a = evidenceRegistry.getEvidence(firstId);
        AVACoreTypes.EvidenceRecord memory b = evidenceRegistry.getEvidence(secondId);
        assert(a.registeredBy == SOURCE_ACTOR && b.registeredBy == SOURCE_ACTOR);
        assert(a.commitment == first.commitment && b.commitment == second.commitment);
    }

    /// @notice Public view diagnostics are warm fixture gas, excluding transaction intrinsic gas.
    function testUsableBindingPublicCallCost() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        uint256 beforeGas = gasleft();
        AVAEvidenceResourceBinding.Binding memory result = bindings.requireUsableBinding(id);
        uint256 used = beforeGas - gasleft();
        require(result.resourceId == RESOURCE, "wrong bound resource");
        emit log_named_uint("usable binding warm public call gas", used);
        require(used < 74_000, "binding repeats already read current flags");
        emit log_named_uint("usable binding calldata bytes", abi.encodeCall(bindings.requireUsableBinding, (id)).length);
    }

    /// @notice Compare the full Core boundary with the duplicate and single binding reads it uses.
    function testCoreBoundEvidencePublicCallCost() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        uint256 beforeGas = gasleft();
        (bytes32 appId, bytes32 workflow, uint256 packageId, bytes32 subject, uint256 disclosure) =
            evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
        uint256 coreGas = beforeGas - gasleft();
        require(
            appId == APP && workflow == REQUEST_WORKFLOW && packageId == requestPackageId
                && subject == _authority(ROLE_SOURCE) && disclosure == requestPolicyId,
            "Core current use returned wrong scope"
        );
        beforeGas = gasleft();
        AVAEvidenceResourceBinding.Binding memory historical = bindings.requireBinding(id);
        AVAEvidenceResourceBinding.Binding memory usable = bindings.requireUsableBinding(id);
        uint256 pairGas = beforeGas - gasleft();
        require(historical.resourceId == RESOURCE && usable.resourceId == RESOURCE, "pair read changed binding");
        beforeGas = gasleft();
        usable = bindings.requireUsableBinding(id);
        uint256 singleGas = beforeGas - gasleft();
        require(usable.resourceId == RESOURCE, "single read changed binding");
        emit log_named_uint("Core bound evidence warm public call gas", coreGas);
        emit log_named_uint("historical plus usable binding warm public calls gas", pairGas);
        emit log_named_uint("single usable binding warm public call gas", singleGas);
        emit log_named_uint("duplicated binding read warm diagnostic delta", pairGas - singleGas);
        emit log_named_uint(
            "Core usable evidence calldata bytes",
            abi.encodeCall(evidenceRegistry.requireUsableEvidenceReferenceForPackage, (id, requestPackageId)).length
        );
    }

    function testBoundPolicyRejectsWrongScopeBeforeKnownUnavailableThenFreshEvidenceWorks() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        IAVAApplicationModule.EvidenceUseContext memory context = IAVAApplicationModule.EvidenceUseContext({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            actionKey: keccak256("ava.core.require-usable-evidence.v1"),
            roleKey: bytes32(0),
            stage: AVACoreTypes.Stage.None,
            targetId: 0,
            objectTypeKey: bytes32(0),
            subjectId: _authority(ROLE_SOURCE),
            evidenceId: id,
            evidenceTypeHash: ENVELOPE,
            disclosurePolicyId: requestPolicyId,
            evidenceStatus: AVACoreTypes.EvidenceStatus.Active,
            authorityId: bytes32(0),
            actor: address(0)
        });
        boundPolicy.validateEvidenceUse(context);
        bytes32 history = keccak256(abi.encode(evidenceRegistry.getEvidence(id), bindings.getBinding(id)));
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.EvidenceUnavailable.selector, id));
        boundPolicy.validateEvidenceUse(context);
        context.appId = keccak256("foreign-app");
        _expectInvalidState(id);
        boundPolicy.validateEvidenceUse(context);
        context.appId = APP;
        context.workflowKey = keccak256("foreign-workflow");
        _expectInvalidState(id);
        boundPolicy.validateEvidenceUse(context);
        context.workflowKey = REQUEST_WORKFLOW;
        context.disclosurePolicyId = requestPolicyId + 1;
        _expectInvalidState(id);
        boundPolicy.validateEvidenceUse(context);
        context.disclosurePolicyId = requestPolicyId;
        context.evidenceTypeHash = keccak256("plaintext-hash");
        _expectInvalidState(id);
        boundPolicy.validateEvidenceUse(context);
        require(
            keccak256(abi.encode(evidenceRegistry.getEvidence(id), bindings.getBinding(id))) == history,
            "scope refusal rewrote history"
        );
        _registerResource(SECOND_RESOURCE, CASE_ID, DIGEST);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory fresh = _input();
        fresh.uri = SECOND_RESOURCE_URI;
        uint256 next = _register(fresh);
        _bind(next, SECOND_RESOURCE);
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(next, requestPackageId);
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(next, requestPackageId),
            "legal evidence blocked after refusal"
        );
    }

    function testResourceGatewayPublicCallCost() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        uint256 beforeGas = gasleft();
        (uint256 returnedId,,,, bool usable) = bindings.resourceBinding(RESOURCE);
        uint256 used = beforeGas - gasleft();
        require(returnedId == id && usable, "wrong gateway binding");
        emit log_named_uint("resource gateway warm public call gas", used);
        require(used < 74_000, "gateway repeats already read current flags");
        emit log_named_uint(
            "resource gateway calldata bytes", abi.encodeCall(bindings.resourceBinding, (RESOURCE)).length
        );
    }

    function testCoreUsabilityHonoursPackageEvidencePolicy() public {
        _upgradePolicy(address(new RejectCurrentUseEvidencePolicy()), false);
        uint256 id = _register(_input());
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
        _expectInvalidState(id);
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId);
        evidenceRegistry.requireEvidenceReferenceForPackage(id, requestPackageId);
    }

    function testAvailabilityRejectsSignalForAnotherReceiptAndInvalidReferences() public {
        _upgradePolicy(address(new MismatchedUnavailableEvidencePolicy()), false);
        uint256 id = _register(_input());
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.EvidenceUnavailable.selector, id + 1));
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId);
        _expectInvalidState(id);
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId + 1);
        _expectInvalidState(0);
        evidenceRegistry.isEvidenceAvailableForPackage(0, requestPackageId);
    }

    function testUnboundEvidenceCannotBecomeUsableUntilExactResourceIsBound() public {
        _boundSetup();
        uint256 id = _register(_input());
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
        requestVm.expectRevert();
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId);
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, id));
        bindings.bindingStatus(id);
        _bind(id, RESOURCE);
        (AVAEvidenceResourceBinding.Binding memory status, bool available) = bindings.bindingStatus(id);
        require(available && status.evidenceId == id && status.resourceId == RESOURCE, "healthy binding status");
        AVAEvidenceResourceBinding.Binding memory binding = bindings.requireUsableBinding(id);
        require(binding.evidenceId == id && binding.resourceId == RESOURCE, "exact evidence-resource pair");
        require(binding.caseId == CASE_ID && binding.privacyPolicyId == privacyPolicyId, "case-policy pin");
        require(binding.materialClass == MATERIAL && binding.ciphertextHash == DIGEST, "material and ciphertext pin");
        require(binding.appId == APP && binding.workflowKey == REQUEST_WORKFLOW, "application-workflow pin");
        require(binding.packageId == requestPackageId && binding.subjectId == _authority(ROLE_SOURCE), "Core scope");
        require(binding.disclosurePolicyId == requestPolicyId, "Core disclosure pin");
        require(bindings.evidenceByResource(RESOURCE) == id, "reverse pin");
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
        require(evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId), "bound receipt available");
    }

    function testPackageIdentityDriftBlocksCurrentBindingButPreservesHistory() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        bindings.requireUsableBinding(id);
        requestVm.etch(address(application), hex"00");
        requestVm.expectRevert();
        bindings.requireUsableBinding(id);
        require(bindings.requireBinding(id).resourceId == RESOURCE, "historical pair survives module drift");
        requestVm.expectRevert();
        bindings.resourceBinding(RESOURCE);
        requestVm.expectRevert();
        bindings.bindingStatus(id);
        requestVm.expectRevert();
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId);
    }

    function testBindingRequiresCurrentAuthorisedSubject() public {
        _boundSetup();
        uint256 id = _register(_input());
        requestVm.expectRevert();
        requestVm.prank(VERIFIER_ACTOR);
        bindings.bindEvidence(id, RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, bindings.BIND_EVIDENCE(), false);
        requestVm.expectRevert();
        _bind(id, RESOURCE);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, bindings.BIND_EVIDENCE(), true);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        requestVm.expectRevert();
        _bind(id, RESOURCE);
        require(bindings.evidenceByResource(RESOURCE) == 0, "failed authority cannot reserve resource");
    }

    function testBindingRejectsResourceFromAnotherApplication() public {
        _boundSetup();
        bytes32 otherApp = keccak256("evidence.binding.other-app");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other-app"), keccak256("other-authority"), address(this), "test:other-app"
        );
        bytes32 otherAuthority = keccak256("evidence.binding.other-source");
        identityRegistry.assignSubject(SOURCE_ACTOR, otherApp, ROLE_SOURCE, otherAuthority, "test:other-source");
        _privacyPermissions(otherApp);
        uint256 otherPolicy = _publishPrivacyPolicy(otherApp);
        bytes32 otherCase = keccak256("evidence.binding.other-case");
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.openCase(otherCase, otherApp, otherPolicy, ROLE_SOURCE, otherAuthority);
        privacy.registerResource(SECOND_RESOURCE, otherCase, MATERIAL, DIGEST, ROLE_SOURCE, otherAuthority);
        requestVm.stopPrank();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.uri = SECOND_RESOURCE_URI;
        uint256 id = _register(input);
        _expectInvalidState(id);
        _bind(id, SECOND_RESOURCE);
        require(bindings.evidenceByResource(SECOND_RESOURCE) == 0, "foreign resource remains unbound");
    }

    function testBindingRejectsWrongCiphertextHash() public {
        _boundSetup();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.commitment = keccak256("different-encrypted-envelope");
        uint256 id = _register(input);
        _expectInvalidState(id);
        _bind(id, RESOURCE);
        require(bindings.evidenceByResource(RESOURCE) == 0, "wrong hash cannot reserve resource");
    }

    function testBindingRejectsWrongEvidenceTypeEvenWithPermissiveCorePolicy() public {
        _privacySetup();
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.evidenceTypeHash = keccak256("plaintext-hash");
        uint256 id = _register(input);
        _expectInvalidState(id);
        _bind(id, RESOURCE);
    }

    function testBindingRequiresExactCanonicalResourceUri() public {
        _boundSetup();
        require(keccak256(bytes(bindings.uriFor(RESOURCE))) == keccak256(bytes(RESOURCE_URI)), "literal canonical URI");
        require(
            keccak256(bytes(bindings.uriFor(bytes32(type(uint256).max))))
                == keccak256(bytes("ava-private:v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
            "lowercase full-width hex"
        );
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.uri = string.concat(RESOURCE_URI, "/");
        uint256 id = _register(input);
        _expectInvalidState(id);
        _bind(id, RESOURCE);
    }

    function testPairCannotBeDuplicatedReboundOrShared() public {
        _boundSetup();
        uint256 id = _register(_input());
        uint256 duplicate = _register(_input());
        _registerResource(SECOND_RESOURCE, CASE_ID, DIGEST);
        _bind(id, RESOURCE);
        _expectInvalidState(id);
        _bind(id, RESOURCE);
        _expectInvalidState(id);
        _bind(id, SECOND_RESOURCE);
        _expectInvalidState(duplicate);
        _bind(duplicate, RESOURCE);
        require(bindings.getBinding(id).resourceId == RESOURCE, "forward pair retained");
        require(bindings.evidenceByResource(RESOURCE) == id, "reverse pair retained");
        require(bindings.evidenceByResource(SECOND_RESOURCE) == 0, "failed rebind is atomic");
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.UnknownReference.selector, duplicate));
        bindings.getBinding(duplicate);
    }

    function testRevokedEvidenceIsUnavailableButBindingRemainsHistorical() public {
        _unavailableEvidence(AVACoreTypes.EvidenceLifecycleKind.Revoke);
    }

    function testExpiredEvidenceIsUnavailableButBindingRemainsHistorical() public {
        _unavailableEvidence(AVACoreTypes.EvidenceLifecycleKind.Expire);
    }

    function testSupersessionUsesFreshResourceAndPreservesBothPairs() public {
        _boundSetup();
        uint256 original = _register(_input());
        _bind(original, RESOURCE);
        bytes32 replacementDigest = keccak256("replacement-encrypted-envelope");
        _registerResource(SECOND_RESOURCE, CASE_ID, replacementDigest);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.commitment = replacementDigest;
        input.uri = SECOND_RESOURCE_URI;
        uint256 replacement = _register(input);
        _bind(replacement, SECOND_RESOURCE);
        _lifecycle(original, AVACoreTypes.EvidenceLifecycleKind.Supersede, replacement);
        _assertUnavailable(original);
        require(
            evidenceRegistry.getEvidence(original).replacementEvidenceId == replacement, "Core replacement retained"
        );
        require(
            bindings.requireUsableBinding(replacement).resourceId == SECOND_RESOURCE, "replacement has fresh resource"
        );
        require(bindings.evidenceByResource(SECOND_RESOURCE) == replacement, "replacement reverse pair");
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(replacement, requestPackageId);
        _expectInvalidState(original);
        _bind(original, SECOND_RESOURCE);
    }

    function testResourceDeactivationBlocksCurrentUseButPreservesHistory() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _assertUnavailable(id);
    }

    function testSubjectDeactivationAfterBindingBlocksCurrentUseButPreservesHistory() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        bindings.requireUsableBinding(id);
        require(evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId), "initial Core availability");
        bytes32 historyHash = keccak256(abi.encode(evidenceRegistry.getEvidence(id), bindings.getBinding(id)));
        bytes32 subject = _authority(ROLE_SOURCE);

        identityRegistry.deactivateSubject(subject);
        require(!evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId), "Core excludes retired subject");
        _assertUnavailable(id);
        require(identityRegistry.getSubject(_authority(ROLE_VERIFIER)).active, "unrelated identity changed");

        bytes32 successor = keccak256("binding.source.successor");
        identityRegistry.assignSubject(SOURCE_ACTOR, APP, ROLE_SOURCE, successor, "test:successor");
        require(identityRegistry.subjectOf(SOURCE_ACTOR, APP, ROLE_SOURCE) == successor, "fresh subject assigned");
        _assertUnavailable(id);
        require(
            keccak256(abi.encode(evidenceRegistry.getEvidence(id), bindings.getBinding(id))) == historyHash,
            "subject retirement or replacement rewrote history"
        );
    }

    function testPrivacyPolicyDeactivationBlocksCurrentUseButPreservesHistory() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivatePolicy(privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _assertUnavailable(id);
    }

    function testBoundProfileRejectsDifferentPrivacyPolicy() public {
        _boundSetup();
        uint256 otherPolicy = _publishPrivacyPolicy(APP);
        bytes32 otherCase = keccak256("evidence.binding.other-policy-case");
        requestVm.prank(SOURCE_ACTOR);
        privacy.openCase(otherCase, APP, otherPolicy, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _registerResource(SECOND_RESOURCE, otherCase, DIGEST);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = _input();
        input.uri = SECOND_RESOURCE_URI;
        uint256 id = _register(input);
        _bind(id, SECOND_RESOURCE);
        require(
            bindings.requireUsableBinding(id).privacyPolicyId == otherPolicy, "generic binding records actual policy"
        );
        _expectInvalidState(id);
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivatePolicy(otherPolicy, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _expectInvalidState(id);
        evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId);
        evidenceRegistry.requireEvidenceReferenceForPackage(id, requestPackageId);
    }

    function testValidHistoricalPackageDoesNotNeedCurrentActivePointer() public {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        uint256 nextPackage = _registerRequestPackage(application, 3);
        require(packageRegistry.getActivePackageId(APP, REQUEST_WORKFLOW) == nextPackage, "active pointer advanced");
        require(bindings.requireUsableBinding(id).packageId == requestPackageId, "binding keeps valid original package");
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
    }

    function _boundSetup() private {
        _privacySetup();
        boundPolicy =
            new AVABoundConfidentialEvidencePolicy(APP, REQUEST_WORKFLOW, requestPolicyId, bindings, privacyPolicyId);
        _upgradePolicy(address(boundPolicy), true);
    }

    function _privacySetup() private {
        privacy = new AVAPrivacyRegistry(authorityMatrix);
        bindings = new AVAEvidenceResourceBinding(privacy, evidenceRegistry);
        _privacyPermissions(APP);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, bindings.BIND_EVIDENCE(), true);
        privacyPolicyId = _publishPrivacyPolicy(APP);
        requestVm.prank(SOURCE_ACTOR);
        privacy.openCase(CASE_ID, APP, privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _registerResource(RESOURCE, CASE_ID, DIGEST);
    }

    function _privacyPermissions(bytes32 appId) private {
        authorityMatrix.setPermission(appId, ROLE_SOURCE, privacy.MANAGE_POLICY(), true);
        authorityMatrix.setPermission(appId, ROLE_SOURCE, privacy.MANAGE_CASE(), true);
        authorityMatrix.setPermission(appId, ROLE_SOURCE, privacy.REGISTER_RESOURCE(), true);
    }

    function _publishPrivacyPolicy(bytes32 appId) private returns (uint256) {
        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](1);
        rules[0].materialClass = MATERIAL;
        rules[0].readerRole = keccak256("evidence.binding.reader");
        rules[0].purpose = keccak256("evidence.binding.purpose");
        rules[0].phaseMask = 1;
        rules[0].maxLeaseSeconds = 3600;
        bytes32 authorityId = identityRegistry.subjectOf(SOURCE_ACTOR, appId, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        return privacy.publishPolicy(appId, ROLE_SOURCE, authorityId, rules);
    }

    function _registerResource(bytes32 resourceId, bytes32 caseId, bytes32 digest) private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.registerResource(resourceId, caseId, MATERIAL, digest, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _unavailableEvidence(AVACoreTypes.EvidenceLifecycleKind kind) private {
        _boundSetup();
        uint256 id = _register(_input());
        _bind(id, RESOURCE);
        _lifecycle(id, kind, 0);
        _assertUnavailable(id);
    }

    function _lifecycle(uint256 id, AVACoreTypes.EvidenceLifecycleKind kind, uint256 replacement) private {
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            id,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            kind,
            replacement,
            keccak256("binding.lifecycle.reason"),
            "test:binding-lifecycle"
        );
    }

    function _assertUnavailable(uint256 id) private {
        require(bindings.requireBinding(id).resourceId == RESOURCE, "historical pair retained");
        require(bindings.getBinding(id).ciphertextHash == DIGEST, "historical digest retained");
        require(bindings.evidenceByResource(RESOURCE) == id, "historical reverse pair retained");
        evidenceRegistry.requireEvidenceReferenceForPackage(id, requestPackageId);
        (uint256 reverseId, bytes32 workflow, uint256 packageId, uint256 policyId, bool usable) =
            bindings.resourceBinding(RESOURCE);
        require(
            reverseId == id && workflow == REQUEST_WORKFLOW && packageId == requestPackageId
                && policyId == requestPolicyId,
            "fixed gateway context retained"
        );
        require(!usable, "gateway denies current use");
        (AVAEvidenceResourceBinding.Binding memory status, bool available) = bindings.bindingStatus(id);
        require(
            !available && status.evidenceId == id && status.resourceId == RESOURCE, "unavailable status lost history"
        );
        require(!evidenceRegistry.isEvidenceAvailableForPackage(id, requestPackageId), "known loss is exclusion");
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.EvidenceUnavailable.selector, id));
        bindings.requireUsableBinding(id);
        requestVm.expectRevert();
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(id, requestPackageId);
    }

    function _bind(uint256 id, bytes32 resource) private {
        requestVm.prank(SOURCE_ACTOR);
        bindings.bindEvidence(id, resource, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _expectInvalidState(uint256 id) private {
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
    }

    function _upgradePolicy(address policy, bool disclosure) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory modules = _coreBindings(application);
        modules[4] = _coreBinding(AVACapabilityKeys.EVIDENCE_POLICY, policy);
        if (disclosure) modules[5] = _coreBinding(AVACapabilityKeys.DISCLOSURE_POLICY, policy);
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:bound-rules"
            ),
            requestPackageId,
            modules
        );
    }

    function _input() private view returns (AVAEvidenceRegistry.EvidenceRegistrationInput memory) {
        return AVAEvidenceRegistry.EvidenceRegistrationInput(
            APP,
            REQUEST_WORKFLOW,
            requestPackageId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            DIGEST,
            ENVELOPE,
            requestPolicyId,
            _authority(ROLE_SOURCE),
            RESOURCE_URI
        );
    }

    function _register(AVAEvidenceRegistry.EvidenceRegistrationInput memory input) private returns (uint256) {
        requestVm.prank(SOURCE_ACTOR);
        return evidenceRegistry.registerEvidence(input);
    }
}
