// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAPrivacyRegistry} from "../src/extensions/privacy/AVAPrivacyRegistry.sol";
import {AVAGovernedDisclosure} from "../src/extensions/privacy/AVAGovernedDisclosure.sol";
import {AVAEvidenceResourceBinding} from "../src/extensions/privacy/AVAEvidenceResourceBinding.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {IAVAEvidencePolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {RejectCurrentUseEvidencePolicy, EvidenceBindingVm} from "./EvidenceResourceBinding.t.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @notice A pinned policy whose current qualification changes at a public time boundary.
contract TimedTargetUseEvidencePolicy is IAVAEvidencePolicyModule, RuleModuleIdentity {
    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) external view {
        if (block.timestamp >= 1200) revert AVACoreTypes.InvalidState(context.evidenceId);
    }
}

contract UnavailableTargetUseEvidencePolicy is IAVAEvidencePolicyModule, RuleModuleIdentity {
    function validateEvidence(IAVAApplicationModule.EvidenceContext calldata) external pure {}

    function validateEvidenceUse(IAVAApplicationModule.EvidenceUseContext calldata context) external pure {
        revert AVACoreTypes.EvidenceUnavailable(context.evidenceId);
    }
}

contract DisclosureTransitionRequester is RuleModuleIdentity {
    function change(AVAGovernanceKernel kernel, AVAGovernanceKernel.SourceBoundTransitionInput calldata input)
        external
    {
        kernel.requestSourceBoundTransition(input);
    }
}

contract GovernedDisclosureTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("disclosure.test.app");
    bytes32 private constant OBJECT = keccak256("disclosure.test.object");
    bytes32 private constant CASE_ID = keccak256("disclosure.test.case");
    bytes32 private constant RESOURCE = keccak256("disclosure.test.resource");
    bytes32 private constant MATERIAL = keccak256("disclosure.test.identity");
    bytes32 private constant PERSONA = keccak256("disclosure.test.random-persona");
    bytes32 private constant READER = keccak256("disclosure.test.panel");
    bytes32 private constant ROUTINE = keccak256("disclosure.test.routine");
    bytes32 private constant PURPOSE = keccak256("disclosure.test.adjudicate");
    bytes32 private constant RESPONSE = keccak256("disclosure.test.authorize-access");
    bytes32 private constant BURDEN = keccak256("disclosure.test.burden");
    AVAPrivacyRegistry private privacy;
    AVAEvidenceResourceBinding private bindings;
    AVAGovernedDisclosure private executor;
    uint64 private requestDeadline = 1600;
    DisclosureTransitionRequester private transitionRequester;
    uint256 private targetEvidenceId;
    uint256 private privacyPolicyId;

    function setUp() public {
        requestVm.warp(1000);
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), OBJECT);
        privacy = new AVAPrivacyRegistry(authorityMatrix);
        bindings = new AVAEvidenceResourceBinding(privacy, evidenceRegistry);
        executor = new AVAGovernedDisclosure(
            privacy, requestAllocation, bindings, APP, REQUEST_WORKFLOW, OBJECT, RESPONSE, BURDEN
        );
        transitionRequester = new DisclosureTransitionRequester();
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, requestAllocation.ACTION_FILE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, requestAllocation.ACTION_RESOLVE_REQUEST_CHALLENGE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_POLICY(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.MANAGE_CASE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.REGISTER_RESOURCE(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, privacy.GRANT_ACCESS(), true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, bindings.BIND_EVIDENCE(), true);
        AVAPrivacyRegistry.Rule[] memory rules = new AVAPrivacyRegistry.Rule[](2);
        rules[0] = AVAPrivacyRegistry.Rule(MATERIAL, READER, ROUTINE, 1, 1000, address(0));
        rules[1] = AVAPrivacyRegistry.Rule(MATERIAL, READER, PURPOSE, 1, 1000, address(executor));
        requestVm.startPrank(SOURCE_ACTOR);
        privacyPolicyId = privacy.publishPolicy(APP, ROLE_SOURCE, _authority(ROLE_SOURCE), rules);
        privacy.openCase(CASE_ID, APP, privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.setMember(CASE_ID, PERSONA, READER, 5000, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.registerResource(
            RESOURCE, CASE_ID, MATERIAL, keccak256("ciphertext"), ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        targetEvidenceId = _evidence(RESOURCE, keccak256("ciphertext"));
        bindings.bindEvidence(targetEvidenceId, RESOURCE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();
    }

    event log_named_uint(string key, uint256 value);

    /// @notice A separate healthy disclosure workflow must not substitute for target qualification.
    function testTargetPolicyVetoRefusesProtectedExecutionWithHealthyDisclosureSupport() public {
        (bytes32 resource, uint256 target, uint256 targetPackage) =
            _policyTarget(address(new RejectCurrentUseEvidencePolicy()));
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, target));
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(target, targetPackage);
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, target));
        evidenceRegistry.isEvidenceAvailableForPackage(target, targetPackage);
        // Structural binding eligibility is deliberately weaker than package policy qualification.
        bindings.requireUsableBinding(target);
        bytes32 targetHistory = keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target)));

        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = resource;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        uint256 support = requestAllocation.getRequest(id).evidenceReceiptId;
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(support, requestPackageId);
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(support, requestPackageId), "disclosure support unavailable"
        );

        (bool executed, bytes memory refusal) =
            address(executor).call(abi.encodeCall(executor.executeDisclosure, (id, parameters)));
        bool current = executor.isGrantCurrent(id);
        bool readable = privacy.canAccess(resource, PERSONA, READER, PURPOSE);
        emit log_named_uint("policy-vetoed target execution succeeded", executed ? 1 : 0);
        emit log_named_uint("policy-vetoed target grant current", current ? 1 : 0);
        emit log_named_uint("policy-vetoed target protected access", readable ? 1 : 0);
        require(
            keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target))) == targetHistory,
            "target history changed"
        );
        require(!executed, "target policy veto bypassed by healthy disclosure support");
        require(
            keccak256(refusal) == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, target)),
            "technical target policy failure was masked"
        );
        require(!current && !readable, "refused target has current access");
        _assertUnconsumed(id);
        _authorizedDisclosure(); // A refused target must not reserve unrelated lawful disclosure.
    }

    function testKnownUnavailableTargetRefusesExecutionWithoutMaskingItsClassification() public {
        (bytes32 resource, uint256 target, uint256 targetPackage) =
            _policyTarget(address(new UnavailableTargetUseEvidencePolicy()));
        require(!evidenceRegistry.isEvidenceAvailableForPackage(target, targetPackage), "target loss not classified");
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = resource;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.EvidenceUnavailable.selector, target));
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        _authorizedDisclosure();
    }

    function testCorrectionPurposeTargetCanBeReadWithIndependentOrdinaryDisclosureSupport() public {
        uint256 historicalPackage = requestPackageId;
        requestPackageId = _registerRequestPackage(new M14PermissiveApplicationModule(APP), 2);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        bytes32 resource = keccak256("disclosure.correction-purpose-target.resource");
        bytes32 digest = keccak256("disclosure.correction-purpose-target.ciphertext");
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.registerResource(resource, CASE_ID, MATERIAL, digest, ROLE_SOURCE, _authority(ROLE_SOURCE));
        uint256 target = evidenceRegistry.registerCorrectionEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput(
                APP,
                REQUEST_WORKFLOW,
                historicalPackage,
                ROLE_SOURCE,
                _authority(ROLE_SOURCE),
                digest,
                keccak256("sha256.encrypted-envelope.v1"),
                requestPolicyId,
                _authority(ROLE_SOURCE),
                bindings.uriFor(resource)
            ),
            requestPackageId,
            keccak256("disclosure.correction-purpose-target.admission")
        );
        bindings.bindEvidence(target, resource, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();
        require(evidenceRegistry.isCorrectionEvidence(target), "target is not correction-purpose evidence");
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, target));
        evidenceRegistry.requireUsableEvidenceReferenceForPackage(target, historicalPackage);
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(target, historicalPackage), "qualified target unavailable"
        );
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = resource;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        executor.executeDisclosure(id, parameters);
        require(executor.isGrantCurrent(id), "correction-purpose target grant not current");
        require(privacy.canAccess(resource, PERSONA, READER, PURPOSE), "qualified correction target unreadable");
    }

    function testTargetPolicyVetoAfterGrantClosesAccessWithoutChangingReceipt() public {
        (bytes32 resource, uint256 target, uint256 targetPackage) =
            _policyTarget(address(new TimedTargetUseEvidencePolicy()));
        require(evidenceRegistry.isEvidenceAvailableForPackage(target, targetPackage), "initial target unavailable");
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = resource;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        executor.executeDisclosure(id, parameters);
        require(executor.isGrantCurrent(id), "initial target grant absent");
        require(privacy.canAccess(resource, PERSONA, READER, PURPOSE), "initial target access absent");
        bytes32 history = keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id)));
        bytes32 targetHistory = keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target)));

        requestVm.warp(1200);
        EvidenceBindingVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, target));
        evidenceRegistry.isEvidenceAvailableForPackage(target, targetPackage);
        uint256 support = requestAllocation.getRequest(id).evidenceReceiptId;
        require(evidenceRegistry.isEvidenceAvailableForPackage(support, requestPackageId), "independent support lost");
        require(!executor.isGrantCurrent(id), "target policy veto left grant current");
        require(!privacy.canAccess(resource, PERSONA, READER, PURPOSE), "target policy veto left protected access");
        require(
            keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id))) == history,
            "policy veto rewrote completed authorization"
        );
        require(
            keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target))) == targetHistory,
            "policy veto rewrote target history"
        );
        _authorizedDisclosure();
        require(!privacy.canAccess(resource, PERSONA, READER, PURPOSE), "legal fallback revived old target grant");
    }

    /// @notice Warm public calls, excluding setup and transaction intrinsic gas.
    function testProtectedTargetQualificationPublicCallCost() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        require(
            bindings.evidenceByResource(parameters.resourceId) != requestAllocation.getRequest(id).evidenceReceiptId,
            "control is not distinct evidence"
        );
        uint256 beforeGas = gasleft();
        bytes32 effect = executor.executeDisclosure(id, parameters);
        uint256 executionGas = beforeGas - gasleft();
        beforeGas = gasleft();
        bool current = executor.isGrantCurrent(id);
        uint256 currentGas = beforeGas - gasleft();
        emit log_named_uint("protected disclosure warm execution call gas", executionGas);
        emit log_named_uint("protected disclosure warm current grant call gas", currentGas);
        emit log_named_uint("protected disclosure execution calldata bytes", abi.encodeCall(executor.executeDisclosure, (id, parameters)).length);
        emit log_named_uint("protected disclosure current grant calldata bytes", abi.encodeCall(executor.isGrantCurrent, (id)).length);
        require(effect != bytes32(0) && current, "healthy target qualification failed");
    }

    function testSharedTargetQualificationPublicCallCostAndResourceFence() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = keccak256(abi.encode("support resource", evidenceRegistry.nextEvidenceId()));
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        uint256 target = bindings.evidenceByResource(parameters.resourceId);
        require(target == requestAllocation.getRequest(id).evidenceReceiptId, "fixture is not shared evidence");
        uint256 beforeGas = gasleft();
        executor.executeDisclosure(id, parameters);
        uint256 executionGas = beforeGas - gasleft();
        beforeGas = gasleft();
        bool current = executor.isGrantCurrent(id);
        uint256 currentGas = beforeGas - gasleft();
        emit log_named_uint("shared target warm execution call gas", executionGas);
        emit log_named_uint("shared target warm current grant call gas", currentGas);
        emit log_named_uint("shared target execution calldata bytes", abi.encodeCall(executor.executeDisclosure, (id, parameters)).length);
        emit log_named_uint("shared target current grant calldata bytes", abi.encodeCall(executor.isGrantCurrent, (id)).length);
        require(executionGas < 849_782 && currentGas < 175_662, "shared binding cost not reduced");
        require(current && privacy.canAccess(parameters.resourceId, PERSONA, READER, PURPOSE), "shared target failed");
        bytes32 history = keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id)));
        _deactivateResource(parameters.resourceId);
        // The default Core policy does not inspect private resource flags: binding still must.
        requestAllocation.validateCurrentSupport(id);
        require(!executor.isGrantCurrent(id), "shared target skipped its resource fence");
        require(!privacy.canAccess(parameters.resourceId, PERSONA, READER, PURPOSE), "retired shared target readable");
        require(
            keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id))) == history,
            "shared target retirement changed history"
        );
    }

    function testRoutineGrantRevisionAndMembershipGenerationAreMonotonic() public {
        require(privacy.membershipGeneration(CASE_ID, PERSONA, READER) == 1, "initial generation");
        require(privacy.grantRevision(RESOURCE, PERSONA, READER, ROUTINE) == 0, "initial revision");
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.grantAccess(RESOURCE, PERSONA, READER, ROUTINE, 1500, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.revokeAccess(RESOURCE, PERSONA, READER, ROUTINE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        privacy.revokeAccess(RESOURCE, PERSONA, READER, ROUTINE, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();
        require(privacy.grantRevision(RESOURCE, PERSONA, READER, ROUTINE) == 3, "revoke did not fence approval");
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, ROUTINE), "revoked access");
    }

    function testProtectedRuleRejectsControllerAndRequiresExactAllocation() public {
        requestVm.expectRevert();
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccess(RESOURCE, PERSONA, READER, PURPOSE, 1500, ROLE_SOURCE, _authority(ROLE_SOURCE));
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        require(!requestAllocation.getRequest(id).consumed, "failed execution consumed");
        _approveRequest(id);
        executor.executeDisclosure(id, parameters);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "allocated access absent");
        AVARequestAllocation.RequestRecord memory request = requestAllocation.getRequest(id);
        require(request.completed && request.triggeredBy == address(this), "atomic completion");
        (address storedExecutor, uint256 storedRequest, bytes32 effectHash) =
            privacy.accessBasis(RESOURCE, PERSONA, READER, PURPOSE);
        require(
            storedExecutor == address(executor) && storedRequest == id && effectHash == request.effectHash,
            "allocation basis"
        );
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
    }

    function testWrongExecutorCannotUseAnotherExecutorsAllocation() public {
        AVAGovernedDisclosure otherExecutor = new AVAGovernedDisclosure(
            privacy, requestAllocation, bindings, APP, REQUEST_WORKFLOW, OBJECT, RESPONSE, BURDEN
        );
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestWithContext(parameters, address(otherExecutor), CASE_ID);
        _approveRequest(id);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        requestVm.expectRevert();
        otherExecutor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
    }

    function testAlteredParametersCannotUseApprovedAllocation() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        parameters.expiresAt = 1499;
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
    }

    function testMembershipRenewalBeforeExecutionRequiresFreshAllocation() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        _renewMember(6000);
        require(privacy.membershipGeneration(CASE_ID, PERSONA, READER) == 2, "renewal generation missing");
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        uint256 fresh = _authorizedDisclosure();
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "fresh generation allocation failed");
        require(executor.getReceipt(fresh).parameters.membershipGeneration == 2, "stale generation granted");
    }

    function testRevocationBeforeExecutionFencesPreviouslyApprovedRequest() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        _revokeProtectedAccess();
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        uint256 fresh = _authorizedDisclosure();
        require(executor.getReceipt(fresh).parameters.grantRevision == 1, "fresh revision not allocated");
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "fresh revision allocation failed");
    }

    function testProtectedGrantRequiresCurrentPolicyPhase() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        requestVm.prank(SOURCE_ACTOR);
        privacy.advancePhase(CASE_ID, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
    }

    function testProtectedLeaseCannotExceedRuleMaximum() public {
        requestDeadline = 2100;
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.expiresAt = 2001;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        parameters.expiresAt = 2000;
        uint256 exactLimit = _requestDisclosure(parameters);
        _approveRequest(exactLimit);
        executor.executeDisclosure(exactLimit, parameters);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, PURPOSE) == 2000, "maximum lease rejected");
    }

    function testProtectedLeaseCannotExceedMembershipDeadline() public {
        _renewMember(1300);
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        parameters.expiresAt = 1300;
        uint256 exactLimit = _requestDisclosure(parameters);
        _approveRequest(exactLimit);
        executor.executeDisclosure(exactLimit, parameters);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, PURPOSE) == 1300, "membership limit rejected");
    }

    function testExpiredParametersLeaveApprovalUnconsumed() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        requestVm.warp(1500);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
    }

    function testProtectedLeaseCannotOutliveTheRequestSupportHorizon() public {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.expiresAt = 1700; // Membership and the 1000-second rule permit this, but the request ends at 1600.
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "lease outlived allocated support");
    }

    function testExpiryClosesDeliveryAndRetainsAuthorizationHistory() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        requestVm.warp(1500);
        _assertClosedWithHistory(id, receiptHash);
    }

    function testMembershipRenewalAfterGrantDoesNotReviveOldLease() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        _renewMember(6000);
        _assertClosedWithHistory(id, receiptHash);
        require(privacy.accessDeadline(RESOURCE, PERSONA, READER, PURPOSE) == 0, "old membership deadline leaked");
    }

    function testRevocationAfterGrantCannotBeReplayedAndKeepsOldReceipt() public {
        uint256 id = _authorizedDisclosure();
        AVAGovernedDisclosure.Receipt memory receipt = executor.getReceipt(id);
        bytes32 receiptHash = keccak256(abi.encode(receipt));
        _revokeProtectedAccess();
        _assertClosedWithHistory(id, receiptHash);
        requestVm.expectRevert();
        executor.executeDisclosure(id, receipt.parameters);
        uint256 fresh = _authorizedDisclosure();
        require(fresh != id && privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "fresh approval unavailable");
        require(keccak256(abi.encode(executor.getReceipt(id))) == receiptHash, "old receipt overwritten");
    }

    function testPhaseAdvanceClosesExistingProtectedLease() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        requestVm.prank(SOURCE_ACTOR);
        privacy.advancePhase(CASE_ID, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _assertClosedWithHistory(id, receiptHash);
    }

    function testCrossCaseSupportCannotAuthorizeTargetResource() public {
        bytes32 otherCase = keccak256("disclosure.other.case");
        requestVm.prank(SOURCE_ACTOR);
        privacy.openCase(otherCase, APP, privacyPolicyId, ROLE_SOURCE, _authority(ROLE_SOURCE));
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        uint256 id = _requestWithContext(parameters, address(executor), otherCase);
        _approveRequest(id);
        requestVm.expectRevert();
        executor.executeDisclosure(id, parameters);
        _assertUnconsumed(id);
    }

    function testTargetResourceRetirementClosesDeliveryWithHistory() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        _deactivateResource(RESOURCE);
        _assertClosedWithHistory(id, receiptHash);
        require(bindings.getBinding(targetEvidenceId).resourceId == RESOURCE, "historical binding lost");
    }

    function testRoutineTargetSubjectDeactivationClosesGatewayBindingWithHistory() public {
        (bytes32 resource, uint256 target, bytes32 subject) = _independentTarget();
        requestVm.prank(SOURCE_ACTOR);
        privacy.grantAccess(resource, PERSONA, READER, ROUTINE, 1500, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(privacy.canAccess(resource, PERSONA, READER, ROUTINE), "initial routine lease absent");
        bindings.requireUsableBinding(target);
        bytes32 history = keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target)));

        identityRegistry.deactivateSubject(subject);
        // A routine lease is independent of Core eligibility; delivery also requires the binding.
        require(privacy.canAccess(resource, PERSONA, READER, ROUTINE), "independent lease was rewritten");
        _assertTargetSubjectUnavailable(resource, target, history);
    }

    function testProtectedTargetSubjectDeactivationClosesDeliveryWithHistory() public {
        (bytes32 resource, uint256 target, bytes32 subject) = _independentTarget();
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        parameters.resourceId = resource;
        uint256 id = _requestDisclosure(parameters);
        _approveRequest(id);
        executor.executeDisclosure(id, parameters);
        require(privacy.canAccess(resource, PERSONA, READER, PURPOSE), "initial protected delivery absent");
        bytes32 receiptHistory = keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id)));
        bytes32 targetHistory = keccak256(abi.encode(evidenceRegistry.getEvidence(target), bindings.getBinding(target)));
        uint256 support = requestAllocation.getRequest(id).evidenceReceiptId;

        identityRegistry.deactivateSubject(subject);
        require(evidenceRegistry.isEvidenceAvailableForPackage(support, requestPackageId), "support lost eligibility");
        bindings.requireUsableBinding(support);
        require(!privacy.canAccess(resource, PERSONA, READER, PURPOSE), "protected target delivery remains open");
        require(!executor.isGrantCurrent(id), "target loss ignored by protected grant");
        _assertTargetSubjectUnavailable(resource, target, targetHistory);
        require(
            keccak256(abi.encode(executor.getReceipt(id), requestAllocation.getRequest(id))) == receiptHistory,
            "completed authorization history changed"
        );
        (address storedExecutor, uint256 storedRequest, bytes32 effectHash) =
            privacy.accessBasis(resource, PERSONA, READER, PURPOSE);
        require(
            storedExecutor == address(executor) && storedRequest == id && effectHash == executor.grantEffectHash(id),
            "protected allocation basis erased"
        );
    }

    function testSupportResourceRetirementClosesDeliveryWithHistory() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        uint256 supportEvidence = requestAllocation.getRequest(id).evidenceReceiptId;
        _deactivateResource(bindings.getBinding(supportEvidence).resourceId);
        _assertClosedWithHistory(id, receiptHash);
    }

    function testTargetCoreEvidenceRevocationClosesDeliveryWithHistory() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        _revokeEvidence(targetEvidenceId);
        _assertClosedWithHistory(id, receiptHash);
    }

    function testSupportCoreEvidenceRevocationClosesDeliveryWithHistory() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        _revokeEvidence(requestAllocation.getRequest(id).evidenceReceiptId);
        _assertClosedWithHistory(id, receiptHash);
    }

    function testSourceCorrectionAndRestorationCannotReviveOldGrant() public {
        uint256 id = _authorizedDisclosure();
        AVAGovernedDisclosure.Receipt memory receipt = executor.getReceipt(id);
        bytes32 receiptHash = keccak256(abi.encode(receipt));
        _changeSource(receipt.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Voided, false);
        _assertClosedWithHistory(id, receiptHash);
        _changeSource(receipt.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored, true);
        AVAGovernanceKernel.RecognisedStateReference memory restored =
            kernel.getRecognisedStateReference(receipt.recognisedStateId);
        require(restored.status == AVACoreTypes.RecognisedStateStatus.Restored, "source not restored");
        require(restored.lastTransitionId != receipt.recognisedStateTransitionId, "restoration reused occurrence");
        _assertClosedWithHistory(id, receiptHash);
        requestVm.expectRevert();
        executor.executeDisclosure(id, receipt.parameters);
    }

    function testFilingEffectConcernDoesNotFreezeButResidualResolutionClosesDelivery() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        (uint256 challenge,) = _fileConcern(id, AVARequestAllocation.ChallengeTarget.Effect);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "filing imposed adverse freeze");
        require(requestAllocation.lastResolutionIdByRequest(id) == 0, "filing finalized correction");
        _resolveConcern(challenge, AVARequestAllocation.ResolutionOutcome.Residual);
        AVARequestAllocation.RequestChallenge memory correction = requestAllocation.getRequestChallenge(challenge);
        require(
            correction.completedAtResolution && correction.effectHashAtResolution == executor.getReceipt(id).effectHash,
            "effect history missing"
        );
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == 0, "residual erased allocation");
        _assertClosedWithHistory(id, receiptHash);
    }

    function testRejectedFinalizedConcernClosesDeliveryNeutrally() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        (uint256 challenge,) = _fileConcern(id, AVARequestAllocation.ChallengeTarget.Allocation);
        _resolveConcern(challenge, AVARequestAllocation.ResolutionOutcome.Rejected);
        require(
            requestAllocation.getRequestChallenge(challenge).outcome == AVARequestAllocation.ResolutionOutcome.Rejected,
            "rejection missing"
        );
        _assertNeutralCorrection(id);
        _assertClosedWithHistory(id, receiptHash);
    }

    function testUnavailableFilingEvidenceClosesDeliveryOnlyAfterNeutralResolution() public {
        uint256 id = _authorizedDisclosure();
        bytes32 receiptHash = keccak256(abi.encode(executor.getReceipt(id)));
        (uint256 challenge, uint256 filingEvidence) = _fileConcern(id, AVARequestAllocation.ChallengeTarget.Effect);
        _revokeEvidence(filingEvidence);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "unresolved concern froze grant");
        _resolveConcern(challenge, AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable);
        AVARequestAllocation.RequestChallenge memory correction = requestAllocation.getRequestChallenge(challenge);
        require(
            correction.outcome == AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable
                && correction.decisionEvidenceId == 0,
            "neutral unavailable closure missing"
        );
        require(correction.evidenceId == filingEvidence, "filing history erased");
        _assertNeutralCorrection(id);
        _assertClosedWithHistory(id, receiptHash);
    }

    function _parameters() private view returns (AVAGovernedDisclosure.DisclosureParameters memory) {
        return AVAGovernedDisclosure.DisclosureParameters({
            resourceId: RESOURCE,
            persona: PERSONA,
            readerRole: READER,
            purpose: PURPOSE,
            expiresAt: 1500,
            membershipGeneration: privacy.membershipGeneration(CASE_ID, PERSONA, READER),
            grantRevision: privacy.grantRevision(RESOURCE, PERSONA, READER, PURPOSE)
        });
    }

    function _policyTarget(address evidencePolicy)
        private
        returns (bytes32 resource, uint256 evidenceId, uint256 packageId)
    {
        bytes32 workflow = keccak256("disclosure.target.policy-veto.workflow");
        AVACoreRulePackageRegistry.ModuleBinding[] memory modules =
            _coreBindings(new M14PermissiveApplicationModule(APP));
        modules[4] = _coreBinding(AVACapabilityKeys.EVIDENCE_POLICY, evidencePolicy);
        packageId = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                workflow,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("disclosure.target.policy-veto.compatibility"),
                "test:target-policy-veto"
            ),
            modules
        );
        resource = keccak256("disclosure.target.policy-veto.resource");
        bytes32 digest = keccak256("disclosure.target.policy-veto.ciphertext");
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.registerResource(resource, CASE_ID, MATERIAL, digest, ROLE_SOURCE, _authority(ROLE_SOURCE));
        evidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput(
                APP,
                workflow,
                packageId,
                ROLE_SOURCE,
                _authority(ROLE_SOURCE),
                digest,
                keccak256("sha256.encrypted-envelope.v1"),
                requestPolicyId,
                _authority(ROLE_SOURCE),
                bindings.uriFor(resource)
            )
        );
        bindings.bindEvidence(evidenceId, resource, ROLE_SOURCE, _authority(ROLE_SOURCE));
        requestVm.stopPrank();
    }

    function _independentTarget() private returns (bytes32 resource, uint256 evidenceId, bytes32 subject) {
        resource = keccak256("disclosure.independent-target.resource");
        subject = keccak256("disclosure.independent-target.subject");
        bytes32 role = keccak256("disclosure.independent-target.role");
        address actor = address(0x7171);
        bytes32 digest = keccak256("disclosure.independent-target.ciphertext");
        identityRegistry.assignSubject(actor, APP, role, subject, "test:independent-target");
        authorityMatrix.setPermission(APP, role, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        requestVm.prank(SOURCE_ACTOR);
        privacy.registerResource(resource, CASE_ID, MATERIAL, digest, ROLE_SOURCE, _authority(ROLE_SOURCE));
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = AVAEvidenceRegistry.EvidenceRegistrationInput(
            APP,
            REQUEST_WORKFLOW,
            requestPackageId,
            role,
            subject,
            digest,
            keccak256("sha256.encrypted-envelope.v1"),
            requestPolicyId,
            subject,
            bindings.uriFor(resource)
        );
        requestVm.prank(actor);
        evidenceId = evidenceRegistry.registerEvidence(input);
        requestVm.prank(SOURCE_ACTOR);
        bindings.bindEvidence(evidenceId, resource, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _assertTargetSubjectUnavailable(bytes32 resource, uint256 evidenceId, bytes32 history) private {
        require(!evidenceRegistry.isEvidenceAvailableForPackage(evidenceId, requestPackageId), "Core target available");
        (uint256 reverseId,,,, bool usable) = bindings.resourceBinding(resource);
        require(reverseId == evidenceId && !usable, "gateway target remains usable");
        requestVm.expectRevert();
        bindings.requireUsableBinding(evidenceId);
        evidenceRegistry.requireEvidenceReferenceForPackage(evidenceId, requestPackageId);
        require(
            keccak256(abi.encode(evidenceRegistry.getEvidence(evidenceId), bindings.getBinding(evidenceId))) == history,
            "target history changed"
        );
        require(identityRegistry.getSubject(_authority(ROLE_SOURCE)).active, "independent source deactivated");
        bindings.requireUsableBinding(targetEvidenceId);
    }

    function _requestDisclosure(AVAGovernedDisclosure.DisclosureParameters memory parameters)
        private
        returns (uint256)
    {
        return _requestWithContext(parameters, address(executor), CASE_ID);
    }

    function _requestWithContext(
        AVAGovernedDisclosure.DisclosureParameters memory parameters,
        address selectedExecutor,
        bytes32 supportCase
    ) private returns (uint256) {
        bytes32 parametersHash = executor.parametersHash(parameters);
        bytes32 commitment =
            requestAllocation.commitmentFor(APP, selectedExecutor, RESPONSE, parametersHash, BURDEN, requestDeadline);
        bytes32 supportResource = keccak256(abi.encode("support resource", evidenceRegistry.nextEvidenceId()));
        bytes32 ciphertextHash = keccak256(abi.encode("support ciphertext", commitment));
        requestVm.startPrank(SOURCE_ACTOR);
        privacy.registerResource(
            supportResource, supportCase, MATERIAL, ciphertextHash, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        uint256 evidenceId = _evidence(supportResource, ciphertextHash);
        bindings.bindEvidence(evidenceId, supportResource, ROLE_SOURCE, _authority(ROLE_SOURCE));
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: OBJECT,
                objectCommitment: commitment,
                parentObjectId: 0,
                subjectId: _authority(ROLE_SOURCE),
                evidenceReceiptId: evidenceId,
                disclosurePolicyId: requestPolicyId,
                metadataHash: commitment,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:disclosure-request"
            })
        );
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 stateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: keccak256("disclosure.formation"),
                reasonURI: "test:formation"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(stateId, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return _createRequest(
            AVARequestAllocation.RequestInput(
                stateId, selectedExecutor, RESPONSE, parametersHash, BURDEN, requestDeadline
            )
        );
    }

    function _authorizedDisclosure() private returns (uint256 id) {
        AVAGovernedDisclosure.DisclosureParameters memory parameters = _parameters();
        id = _requestDisclosure(parameters);
        _approveRequest(id);
        executor.executeDisclosure(id, parameters);
        require(privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "initial authorization failed");
    }

    function _assertUnconsumed(uint256 id) private view {
        AVARequestAllocation.RequestRecord memory request = requestAllocation.getRequest(id);
        require(
            !request.consumed && !request.completed && request.effectHash == bytes32(0), "failed grant partly committed"
        );
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "failed grant opened access");
        require(executor.grantEffectHash(id) == bytes32(0), "failed grant wrote receipt");
    }

    function _assertClosedWithHistory(uint256 id, bytes32 expectedReceiptHash) private view {
        require(!privacy.canAccess(RESOURCE, PERSONA, READER, PURPOSE), "future delivery remains open");
        AVAGovernedDisclosure.Receipt memory receipt = executor.getReceipt(id);
        require(keccak256(abi.encode(receipt)) == expectedReceiptHash, "authorization receipt changed");
        AVARequestAllocation.RequestRecord memory request = requestAllocation.getRequest(id);
        require(
            request.consumed && request.completed && request.effectHash == receipt.effectHash, "completed effect erased"
        );
        (address storedExecutor, uint256 storedRequest, bytes32 effectHash) =
            privacy.accessBasis(RESOURCE, PERSONA, READER, PURPOSE);
        require(
            storedExecutor == address(executor) && storedRequest == id && effectHash == receipt.effectHash,
            "allocation basis erased"
        );
    }

    function _assertNeutralCorrection(uint256 id) private view {
        require(
            requestAllocation.withdrawalResolutionIdByRequest(id) == 0 && !requestAllocation.getRequest(id).cancelled,
            "neutral closure imposed adverse allocation decision"
        );
        uint256 stateId = requestAllocation.getRequest(id).input.recognisedStateId;
        require(
            kernel.getRecognisedStateReference(stateId).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "neutral closure corrected source"
        );
    }

    function _renewMember(uint64 expiresAt) private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.setMember(CASE_ID, PERSONA, READER, expiresAt, true, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _revokeProtectedAccess() private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.revokeAccess(RESOURCE, PERSONA, READER, PURPOSE, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _deactivateResource(bytes32 resourceId) private {
        requestVm.prank(SOURCE_ACTOR);
        privacy.deactivateResource(resourceId, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _revokeEvidence(uint256 evidenceId) private {
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidenceId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("disclosure.revoke"),
            "test:revoke"
        );
    }

    function _fileConcern(uint256 id, AVARequestAllocation.ChallengeTarget target)
        private
        returns (uint256 challenge, uint256 filingEvidence)
    {
        filingEvidence = _correctionEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        challenge = requestAllocation.fileRequestChallenge(
            id, target, filingEvidence, ROLE_SOURCE, _authority(ROLE_SOURCE), keccak256("disclosure.concern")
        );
    }

    function _resolveConcern(uint256 challenge, AVARequestAllocation.ResolutionOutcome outcome) private {
        uint256 decisionEvidence = outcome == AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable
            ? 0
            : _correctionEvidence(VERIFIER_ACTOR, ROLE_VERIFIER);
        AVARequestAllocation.ResolutionInput memory input = AVARequestAllocation.ResolutionInput({
            challengeId: challenge,
            expectedPreviousResolutionId: 0,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: decisionEvidence,
            outcome: outcome,
            reasonHash: keccak256("disclosure.independent-decision"),
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(
                outcome == AVARequestAllocation.ResolutionOutcome.Rejected
                    || outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn
                    || outcome == AVARequestAllocation.ResolutionOutcome.Residual
                    || outcome == AVARequestAllocation.ResolutionOutcome.Compensate
            )
        });
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
    }

    function _correctionEvidence(address actor, bytes32 role) private returns (uint256) {
        bytes32 commitment = keccak256(abi.encode("disclosure.correction", evidenceRegistry.nextEvidenceId()));
        requestVm.prank(actor);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: role,
                subjectId: _authority(role),
                commitment: commitment,
                evidenceTypeHash: keccak256("correction.decision"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(role),
                uri: "test:correction"
            })
        );
    }

    function _changeSource(uint256 stateId, AVACoreTypes.RecognisedStateStatus toStatus, bool restoration) private {
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(stateId);
        transitionRequester.change(
            kernel,
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: stateId,
                expectedTransitionId: state.lastTransitionId,
                decisionPackageId: state.packageId,
                sourceRecordId: 1,
                decisionEvidenceReceiptId: state.evidenceReceiptId,
                disclosureTargetId: state.governedObjectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                actionKey: restoration ? AVACoreTypes.ACTION_APPLY_RESTORATION : AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                decisionHash: keccak256(abi.encode("disclosure.source-decision", toStatus)),
                toStatus: toStatus,
                kind: restoration
                    ? AVACoreTypes.TransitionKind.Restoration
                    : AVACoreTypes.TransitionKind.ChallengeCorrection,
                reasonHash: keccak256("disclosure.source-correction"),
                reasonURI: "test:source-correction"
            })
        );
    }

    function _evidence(bytes32 resourceId, bytes32 commitment) private returns (uint256) {
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: commitment,
                evidenceTypeHash: keccak256("sha256.encrypted-envelope.v1"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: bindings.uriFor(resourceId)
            })
        );
    }
}
