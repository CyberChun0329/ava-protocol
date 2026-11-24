// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVARequestAllocation} from "../requests/AVARequestAllocation.sol";
import {AVAPrivacyRegistry} from "./AVAPrivacyRegistry.sol";
import {AVAEvidenceResourceBinding} from "./AVAEvidenceResourceBinding.sol";

/// @notice Executes an exact, once-only Allocation that authorizes a protected access lease.
/// @dev An effect means ACCESS AUTHORIZED, never plaintext delivery. The off-chain custodian
/// must authenticate the persona and recheck current access before every delivery. Any finalized
/// request correction after the grant fences future delivery pending a fresh Allocation, including
/// Rejected and EvidenceUnavailable outcomes. This neutral delivery control makes no adverse
/// judgment, erases no history, and is not triggered merely by filing a challenge.
contract AVAGovernedDisclosure {
    bytes32 private constant PARAMETERS_DOMAIN = keccak256("ava.protected-disclosure.parameters.v1");
    bytes32 private constant DECISION_DOMAIN = keccak256("ava.protected-disclosure.allocation.v1");
    bytes32 private constant EFFECT_DOMAIN = keccak256("ava.protected-disclosure.access-authorized.v1");

    struct DisclosureParameters {
        bytes32 resourceId;
        bytes32 persona;
        bytes32 readerRole;
        bytes32 purpose;
        uint64 expiresAt;
        uint256 membershipGeneration;
        uint256 grantRevision;
    }

    struct Receipt {
        uint256 requestId;
        uint256 recognisedStateId;
        uint256 recognisedStateTransitionId;
        uint256 packageId;
        uint256 evidenceReceiptId;
        uint256 targetEvidenceId;
        DisclosureParameters parameters;
        bytes32 parametersHash;
        address allocator;
        bytes32 allocatorRoleKey;
        bytes32 allocatorAuthorityId;
        bytes32 decisionHash;
        bytes32 effectHash;
        uint256 resolutionHead;
        uint64 grantedAt;
    }

    AVARequestAllocation public immutable REQUEST_ALLOCATION;
    AVAPrivacyRegistry public immutable PRIVACY_REGISTRY;
    AVAEvidenceResourceBinding public immutable EVIDENCE_BINDINGS;
    bytes32 public immutable APP_ID;
    bytes32 public immutable WORKFLOW_KEY;
    bytes32 public immutable OBJECT_TYPE;
    bytes32 public immutable RESPONSE_CLASS;
    bytes32 public immutable BURDEN_HASH;
    mapping(uint256 => Receipt) private receipts;

    event DisclosureAuthorized(uint256 indexed requestId, bytes32 indexed resourceId, bytes32 effectHash);

    constructor(
        AVAPrivacyRegistry privacy,
        AVARequestAllocation allocation,
        AVAEvidenceResourceBinding bindings,
        bytes32 appId,
        bytes32 workflowKey,
        bytes32 objectTypeKey,
        bytes32 responseClass,
        bytes32 burdenHash
    ) {
        if (
            address(privacy).code.length == 0 || address(allocation).code.length == 0
                || address(bindings).code.length == 0 || appId == bytes32(0) || workflowKey == bytes32(0)
                || objectTypeKey == bytes32(0) || responseClass == bytes32(0) || burdenHash == bytes32(0)
        ) revert AVACoreTypes.EmptyValue();
        if (
            address(privacy.AUTHORITY_MATRIX()) != address(allocation.AUTHORITY_MATRIX())
                || address(bindings.PRIVACY_REGISTRY()) != address(privacy)
                || address(bindings.EVIDENCE_REGISTRY()) != address(allocation.EVIDENCE_REGISTRY())
        ) revert AVACoreTypes.InvalidState(0);
        PRIVACY_REGISTRY = privacy;
        REQUEST_ALLOCATION = allocation;
        EVIDENCE_BINDINGS = bindings;
        APP_ID = appId;
        WORKFLOW_KEY = workflowKey;
        OBJECT_TYPE = objectTypeKey;
        RESPONSE_CLASS = responseClass;
        BURDEN_HASH = burdenHash;
    }

    /// @dev The Core commitment additionally binds this hash to chain, Allocation host and executor.
    function parametersHash(DisclosureParameters memory parameters) public pure returns (bytes32) {
        return keccak256(abi.encode(PARAMETERS_DOMAIN, parameters));
    }

    /// @notice Anyone may trigger the exact approved instruction; caller identity grants no authority.
    function executeDisclosure(uint256 requestId, DisclosureParameters calldata parameters)
        external
        returns (bytes32 effectHash)
    {
        if (
            parameters.resourceId == bytes32(0) || parameters.persona == bytes32(0)
                || parameters.readerRole == bytes32(0) || parameters.purpose == bytes32(0)
                || parameters.expiresAt <= block.timestamp || parameters.membershipGeneration == 0
                || receipts[requestId].requestId != 0
        ) revert AVACoreTypes.InvalidState(requestId);
        AVARequestAllocation.RequestRecord memory request = REQUEST_ALLOCATION.getRequest(requestId);
        // Keep the wall-clock lease within the request's support horizon, including on a stalled chain.
        if (parameters.expiresAt > request.input.validUntil) revert AVACoreTypes.InvalidState(requestId);
        bytes32 hash = parametersHash(parameters);
        _requireRequestScope(request, hash);
        uint256 targetEvidenceId = _requireBoundEvidence(request, parameters.resourceId);
        REQUEST_ALLOCATION.consume(requestId, RESPONSE_CLASS, hash, msg.sender);
        PRIVACY_REGISTRY.grantAllocatedAccess(
            requestId,
            parameters.resourceId,
            parameters.persona,
            parameters.readerRole,
            parameters.purpose,
            parameters.expiresAt,
            parameters.membershipGeneration,
            parameters.grantRevision
        );
        bytes32 decisionHash = keccak256(
            abi.encode(
                DECISION_DOMAIN,
                block.chainid,
                address(REQUEST_ALLOCATION),
                requestId,
                request.recognisedStateTransitionId,
                request.allocator,
                request.allocatorRoleKey,
                request.allocatorAuthorityId,
                request.approvedAt,
                hash,
                BURDEN_HASH
            )
        );
        uint256 resolutionHead = REQUEST_ALLOCATION.lastResolutionIdByRequest(requestId);
        effectHash = keccak256(
            abi.encode(
                EFFECT_DOMAIN,
                block.chainid,
                address(this),
                requestId,
                request.recognisedStateTransitionId,
                request.packageId,
                request.evidenceReceiptId,
                targetEvidenceId,
                hash,
                decisionHash,
                resolutionHead,
                block.timestamp
            )
        );
        receipts[requestId] = Receipt({
            requestId: requestId,
            recognisedStateId: request.input.recognisedStateId,
            recognisedStateTransitionId: request.recognisedStateTransitionId,
            packageId: request.packageId,
            evidenceReceiptId: request.evidenceReceiptId,
            targetEvidenceId: targetEvidenceId,
            parameters: parameters,
            parametersHash: hash,
            allocator: request.allocator,
            allocatorRoleKey: request.allocatorRoleKey,
            allocatorAuthorityId: request.allocatorAuthorityId,
            decisionHash: decisionHash,
            effectHash: effectHash,
            resolutionHead: resolutionHead,
            grantedAt: uint64(block.timestamp)
        });
        REQUEST_ALLOCATION.complete(requestId, effectHash);
        emit DisclosureAuthorized(requestId, parameters.resourceId, effectHash);
    }

    function getReceipt(uint256 requestId) external view returns (Receipt memory) {
        if (receipts[requestId].requestId == 0) revert AVACoreTypes.UnknownReference(requestId);
        return receipts[requestId];
    }

    function grantEffectHash(uint256 requestId) external view returns (bytes32) {
        return receipts[requestId].effectHash;
    }

    /// @notice Actor-neutral current support for a historical authorization, without recursion into canAccess.
    /// @dev Source restoration changes its transition occurrence and cannot revive this receipt.
    function isGrantCurrent(uint256 requestId) external view returns (bool) {
        Receipt storage receipt = receipts[requestId];
        if (receipt.requestId == 0) return false;
        AVARequestAllocation.RequestRecord memory request = REQUEST_ALLOCATION.getRequest(requestId);
        if (
            !request.completed || request.cancelled || request.effectHash != receipt.effectHash
                || REQUEST_ALLOCATION.lastResolutionIdByRequest(requestId) != receipt.resolutionHead
        ) return false;
        try REQUEST_ALLOCATION.validateCurrentSupport(requestId) returns (bytes32) {}
        catch {
            return false;
        }
        try EVIDENCE_BINDINGS.requireUsableBinding(receipt.targetEvidenceId) returns (
            AVAEvidenceResourceBinding.Binding memory target
        ) {
            if (target.resourceId != receipt.parameters.resourceId || target.appId != APP_ID) return false;
            // Exact shared support was fully qualified by validateCurrentSupport above.
            if (receipt.targetEvidenceId != receipt.evidenceReceiptId || target.packageId != receipt.packageId) {
                try EVIDENCE_BINDINGS.EVIDENCE_REGISTRY()
                    .isEvidenceAvailableForPackage(receipt.targetEvidenceId, target.packageId) returns (
                    bool qualified
                ) {
                    if (!qualified) return false;
                } catch {
                    return false;
                }
            }
            AVAEvidenceResourceBinding.Binding memory support = target;
            if (receipt.targetEvidenceId != receipt.evidenceReceiptId) {
                try EVIDENCE_BINDINGS.requireUsableBinding(receipt.evidenceReceiptId) returns (
                    AVAEvidenceResourceBinding.Binding memory distinctSupport
                ) {
                    support = distinctSupport;
                } catch {
                    return false;
                }
            }
            return support.appId == APP_ID && support.caseId == target.caseId && support.workflowKey == WORKFLOW_KEY
                && support.packageId == receipt.packageId && support.subjectId == request.subjectId;
        } catch {
            return false;
        }
    }

    function _requireRequestScope(AVARequestAllocation.RequestRecord memory request, bytes32 hash) private view {
        if (
            request.appId != APP_ID || request.workflowKey != WORKFLOW_KEY || request.input.executor != address(this)
                || request.input.responseClass != RESPONSE_CLASS || request.input.burdenHash != BURDEN_HASH
                || request.input.parametersHash != hash
        ) revert AVACoreTypes.InvalidState(request.id);
        AVAGovernanceKernel kernel = REQUEST_ALLOCATION.GOVERNANCE_KERNEL();
        AVAGovernanceKernel.RecognisedStateReference memory source =
            kernel.getRecognisedStateReference(request.input.recognisedStateId);
        if (kernel.getGovernedObjectReference(source.governedObjectId).objectTypeKey != OBJECT_TYPE) {
            revert AVACoreTypes.InvalidState(request.id);
        }
    }

    function _requireBoundEvidence(AVARequestAllocation.RequestRecord memory request, bytes32 resourceId)
        private
        view
        returns (uint256)
    {
        uint256 evidenceId = EVIDENCE_BINDINGS.evidenceByResource(resourceId);
        AVAEvidenceResourceBinding.Binding memory target = EVIDENCE_BINDINGS.requireUsableBinding(evidenceId);
        AVAEvidenceResourceBinding.Binding memory support = evidenceId == request.evidenceReceiptId
            ? target
            : EVIDENCE_BINDINGS.requireUsableBinding(request.evidenceReceiptId);
        if (
            target.resourceId != resourceId || target.appId != APP_ID || support.appId != APP_ID
                || support.caseId != target.caseId || support.workflowKey != WORKFLOW_KEY
                || support.packageId != request.packageId || support.subjectId != request.subjectId
        ) revert AVACoreTypes.InvalidState(request.id);
        // Reading authority and current target qualification are separate requirements. Generic
        // availability permits a correction-purpose target without treating it as ordinary support.
        // consume subsequently qualifies exact shared support before any grant can commit.
        if (
            (evidenceId != request.evidenceReceiptId || target.packageId != request.packageId)
                && !EVIDENCE_BINDINGS.EVIDENCE_REGISTRY().isEvidenceAvailableForPackage(evidenceId, target.packageId)
        ) revert AVACoreTypes.EvidenceUnavailable(evidenceId);
        return evidenceId;
    }
}
