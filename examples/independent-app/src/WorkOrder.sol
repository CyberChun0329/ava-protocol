// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "@ava-protocol/contracts/src/core/AVACoreTypes.sol";
import {IAVAApplicationModule} from "@ava-protocol/contracts/src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "@ava-protocol/contracts/src/interfaces/IRuleModuleIdentity.sol";
import {
    AVARequestAllocation,
    AVARequestCorrectionActions
} from "@ava-protocol/contracts/src/extensions/requests/AVARequestAllocation.sol";
import {AVAGovernanceKernel} from "@ava-protocol/contracts/src/core/AVAGovernanceKernel.sol";

library WorkOrder {
    bytes32 internal constant APP = keccak256("independent.work-order.app.v1");
    bytes32 internal constant WORKFLOW = keccak256("independent.work-order.workflow.v1");
    bytes32 internal constant OBJECT = keccak256("independent.work-order.object.v1");
    bytes32 internal constant REQUESTER = keccak256("independent.work-order.role.requester.v1");
    bytes32 internal constant INSPECTOR = keccak256("independent.work-order.role.inspector.v1");
    bytes32 internal constant MANAGER = keccak256("independent.work-order.role.manager.v1");
    bytes32 internal constant CLOSE = keccak256("independent.work-order.response.close.v1");
    bytes32 internal constant BURDEN = keccak256("independent.work-order.burden.inspection.v1");
}

/// @notice App-owned workflow semantics; generic AVA modules retain authority and transition checks.
contract WorkOrderModule is IAVAApplicationModule, RuleModuleIdentity {
    function applicationId() external pure returns (bytes32) {
        return WorkOrder.APP;
    }

    function validateGovernedObject(GovernedObjectContext calldata c) external pure virtual {
        require(
            c.appId == WorkOrder.APP && c.objectTypeKey == WorkOrder.OBJECT && c.roleKey == WorkOrder.REQUESTER
                && c.parentObjectId == 0,
            "Invalid work order"
        );
    }

    function validateEvidence(EvidenceContext calldata c) external pure {
        require(c.appId == WorkOrder.APP && c.roleKey == WorkOrder.REQUESTER, "Requester evidence required");
    }

    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata c) external pure {
        require(
            c.appId == WorkOrder.APP && c.objectTypeKey == WorkOrder.OBJECT && c.roleKey == WorkOrder.INSPECTOR
                && c.stage == AVACoreTypes.Stage.Verification
                && c.status == AVACoreTypes.RecognisedStateStatus.Provisional,
            "Inspector recognition required"
        );
    }

    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata c) external pure {
        require(
            c.appId == WorkOrder.APP && c.objectTypeKey == WorkOrder.OBJECT && c.roleKey == WorkOrder.INSPECTOR
                && c.stage == AVACoreTypes.Stage.Verification,
            "Inspector transition required"
        );
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata c) external pure {
        require(
            c.appId == WorkOrder.APP && c.objectTypeKey == WorkOrder.OBJECT && c.recordTypeKey == WorkOrder.CLOSE,
            "Invalid closure response"
        );
        if (c.actionKey == AVARequestCorrectionActions.FILE && c.roleKey == WorkOrder.REQUESTER) return;
        if (c.actionKey == AVARequestCorrectionActions.RESOLVE && c.roleKey == WorkOrder.INSPECTOR) return;
        require(
            c.actionKey == AVACoreTypes.ACTION_RECORD_ALLOCATION && c.roleKey == WorkOrder.MANAGER,
            "Manager Allocation required"
        );
    }
}

/// @notice Minimal nonfinancial effect adapter: an order receives one immutable closure receipt.
/// @dev Synthetic local management app. Recorded inspection does not certify physical completion.
contract WorkOrderLedger {
    AVARequestAllocation public immutable REQUESTS;

    struct Receipt {
        uint256 requestId;
        uint256 recognisedStateId;
        uint256 sourceTransitionId;
        bytes32 orderId;
        bytes32 completionHash;
        bytes32 effectHash;
    }
    mapping(bytes32 => uint256) public closedByRequest;
    mapping(uint256 => Receipt) private receipts;
    event WorkOrderClosed(bytes32 indexed orderId, uint256 indexed requestId, bytes32 effectHash);

    constructor(AVARequestAllocation requests) {
        REQUESTS = requests;
    }

    function closeOrder(uint256 requestId, bytes32 orderId, bytes32 completionHash) external {
        require(
            orderId != bytes32(0) && completionHash != bytes32(0) && closedByRequest[orderId] == 0,
            "Order already closed or empty"
        );
        AVARequestAllocation.RequestRecord memory request = REQUESTS.getRequest(requestId);
        AVAGovernanceKernel kernel = REQUESTS.GOVERNANCE_KERNEL();
        AVAGovernanceKernel.RecognisedStateReference memory source =
            kernel.getRecognisedStateReference(request.input.recognisedStateId);
        AVAGovernanceKernel.GovernedObjectReference memory object =
            kernel.getGovernedObjectReference(source.governedObjectId);
        require(
            request.appId == WorkOrder.APP && object.objectTypeKey == WorkOrder.OBJECT
                && REQUESTS.EVIDENCE_REGISTRY().getEvidenceReference(source.evidenceReceiptId).commitment
                    == completionHash,
            "Wrong work-order inspection"
        );
        // consume rechecks exact parameters, live evidence/source, expiry and current manager authority.
        REQUESTS.consume(requestId, WorkOrder.CLOSE, keccak256(abi.encode(orderId, completionHash)), msg.sender);
        bytes32 effectHash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                requestId,
                request.input.recognisedStateId,
                request.recognisedStateTransitionId,
                orderId,
                completionHash
            )
        );
        closedByRequest[orderId] = requestId;
        receipts[requestId] =
            Receipt(requestId, source.id, request.recognisedStateTransitionId, orderId, completionHash, effectHash);
        REQUESTS.complete(requestId, effectHash);
        emit WorkOrderClosed(orderId, requestId, effectHash);
    }

    function getReceipt(uint256 requestId) external view returns (Receipt memory) {
        return receipts[requestId];
    }
}
