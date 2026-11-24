// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVAWorkflowPolicyRouter} from "../src/core/AVAWorkflowPolicyRouter.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @notice Test-only contract-account caller, not a production wallet or a Safe implementation.
contract TwoApproverAdministrationFixture {
    address public immutable FIRST;
    address public immutable SECOND;
    uint256 public nonce;
    mapping(bytes32 => mapping(address => bool)) private approvals;

    constructor(address first, address second) {
        FIRST = first;
        SECOND = second;
    }

    function approve(address target, bytes calldata data) external {
        require(msg.sender == FIRST || msg.sender == SECOND, "fixture approver");
        bytes32 operation = keccak256(abi.encode(block.chainid, address(this), nonce, target, data));
        require(!approvals[operation][msg.sender], "duplicate approval");
        approvals[operation][msg.sender] = true;
        if (approvals[operation][FIRST] && approvals[operation][SECOND]) {
            ++nonce;
            (bool success, bytes memory reason) = target.call(data);
            if (!success) {
                assembly ("memory-safe") { revert(add(reason, 32), mload(reason)) }
            }
        }
    }
}

contract ContinuityCounter {
    uint256 public effects;

    function execute(AVARequestAllocation allocation, uint256 id, bytes32 response, bytes32 parameters) external {
        allocation.consume(id, response, parameters, msg.sender);
        ++effects;
        allocation.complete(id, keccak256(abi.encode("continuity.effect", effects)));
    }
}

/// @notice Local operational rehearsals through unchanged public Core interfaces.
contract OperationsContinuityTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("operations.continuity.app");
    bytes32 private constant RESPONSE = keccak256("operations.continuity.response");
    bytes32 private constant PARAMETERS = keccak256("operations.continuity.occurrence.1");
    bytes32 private constant BURDEN = keccak256("operations.continuity.burden");
    address private constant FIRST = address(0xE11);
    address private constant SECOND = address(0xE22);

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("operations.object"));
    }

    function testContractAccountAdminHandoverNeedsBothApprovalsAndPreservesBusinessAuthority() public {
        ContinuityCounter counter = new ContinuityCounter();
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 source = _createRequestState(address(counter), RESPONSE, PARAMETERS, BURDEN, expiry);
        bytes32 sourceHistory = keccak256(abi.encode(kernel.getRecognisedState(source)));
        TwoApproverAdministrationFixture manager = new TwoApproverAdministrationFixture(FIRST, SECOND);
        applicationRegistry.proposeAdmin(address(manager));
        bytes memory accept = abi.encodeCall(applicationRegistry.acceptAdmin, ());
        requestVm.prank(FIRST);
        manager.approve(address(applicationRegistry), accept);
        require(applicationRegistry.ADMIN() == address(this), "one approval transferred root");
        requestVm.prank(FIRST);
        requestVm.expectRevert();
        manager.approve(address(applicationRegistry), accept);
        requestVm.prank(SECOND);
        manager.approve(address(applicationRegistry), accept);
        require(applicationRegistry.ADMIN() == address(manager), "contract root not accepted");
        _both(
            manager,
            address(applicationRegistry),
            abi.encodeCall(applicationRegistry.proposeApplicationAdmin, (APP, address(manager)))
        );
        _both(manager, address(applicationRegistry), abi.encodeCall(applicationRegistry.acceptApplicationAdmin, (APP)));
        requestVm.expectRevert();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        requestVm.prank(FIRST);
        requestVm.expectRevert();
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false);
        _both(
            manager,
            address(authorityMatrix),
            abi.encodeCall(
                authorityMatrix.setPermission, (APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, false)
            )
        );
        require(!authorityMatrix.isAuthorised(SOURCE_ACTOR, APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE));
        _both(
            manager,
            address(authorityMatrix),
            abi.encodeCall(
                authorityMatrix.setPermission, (APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true)
            )
        );
        uint256 id = _createRequest(
            AVARequestAllocation.RequestInput(source, address(counter), RESPONSE, PARAMETERS, BURDEN, expiry)
        );
        _approveRequest(id);
        counter.execute(requestAllocation, id, RESPONSE, PARAMETERS);
        requestVm.expectRevert();
        counter.execute(requestAllocation, id, RESPONSE, PARAMETERS);
        require(counter.effects() == 1 && keccak256(abi.encode(kernel.getRecognisedState(source))) == sourceHistory);
        require(
            !authorityMatrix.isAuthorised(address(manager), APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE),
            "administration became business authority"
        );
    }

    function testNewCoreUsesExplicitNewOccurrenceAndDoesNotImportOldRecognitionOrEffect() public {
        ContinuityCounter counter = new ContinuityCounter();
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 source = _createRequestState(address(counter), RESPONSE, PARAMETERS, BURDEN, expiry);
        AVARequestAllocation oldAllocation = requestAllocation;
        AVAGovernanceKernel oldKernel = kernel;
        uint256 oldRequest = _createRequest(
            AVARequestAllocation.RequestInput(source, address(counter), RESPONSE, PARAMETERS, BURDEN, expiry)
        );
        _approveRequest(oldRequest);
        counter.execute(oldAllocation, oldRequest, RESPONSE, PARAMETERS);
        bytes32 oldHistory =
            keccak256(abi.encode(oldKernel.getRecognisedState(source), oldAllocation.getRequest(oldRequest)));
        kernel = new AVAGovernanceKernel(
            authorityMatrix,
            identityRegistry,
            packageRegistry,
            evidenceRegistry,
            disclosureRegistry,
            new AVAWorkflowPolicyRouter(packageRegistry, evidenceRegistry, disclosureRegistry)
        );
        requestAllocation = new AVARequestAllocation(kernel);
        kernel.CORRECTIONS().bindRequestOrigin(APP, address(requestAllocation));
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createRequest(
            AVARequestAllocation.RequestInput(source, address(counter), RESPONSE, PARAMETERS, BURDEN, expiry),
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
        require(requestAllocation.nextRequestId() == 1, "old reference imported");
        bytes32 newOccurrence = keccak256("operations.continuity.occurrence.2");
        uint256 freshSource = _createRequestState(address(counter), RESPONSE, newOccurrence, BURDEN, expiry);
        uint256 fresh = _createRequest(
            AVARequestAllocation.RequestInput(freshSource, address(counter), RESPONSE, newOccurrence, BURDEN, expiry)
        );
        _approveRequest(fresh);
        counter.execute(requestAllocation, fresh, RESPONSE, newOccurrence);
        require(address(oldKernel) != address(kernel) && oldAllocation.getRequest(oldRequest).completed);
        require(
            keccak256(abi.encode(oldKernel.getRecognisedState(source), oldAllocation.getRequest(oldRequest)))
                == oldHistory,
            "migration rewrote historical host"
        );
        require(counter.effects() == 2, "distinct fresh occurrence did not execute");
        requestVm.expectRevert();
        counter.execute(oldAllocation, oldRequest, RESPONSE, PARAMETERS);
    }

    function testDurableBusinessSubjectSurvivesOperatorRetirementWithoutTransferringAuthority() public {
        bytes32 entity = keccak256("operations.durable.business.subject");
        identityRegistry.assignSubject(address(0xE33), APP, keccak256("operations.entity.role"), entity, "test:entity");
        ContinuityCounter counter = new ContinuityCounter();
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 commitment =
            requestAllocation.commitmentFor(APP, address(counter), RESPONSE, PARAMETERS, BURDEN, expiry);
        requestVm.startPrank(SOURCE_ACTOR);
        AVAEvidenceRegistry.EvidenceRegistrationInput memory evidence = AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            roleKey: ROLE_SOURCE,
            subjectId: entity,
            commitment: keccak256("durable evidence"),
            evidenceTypeHash: keccak256("durable report"),
            disclosurePolicyId: requestPolicyId,
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:durable-evidence"
        });
        uint256 evidenceId = evidenceRegistry.registerEvidence(evidence);
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: requestObjectTypeKey,
                objectCommitment: commitment,
                parentObjectId: 0,
                subjectId: entity,
                evidenceReceiptId: evidenceId,
                disclosurePolicyId: requestPolicyId,
                metadataHash: commitment,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:durable-object"
            })
        );
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 source = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: keccak256("durable verification"),
                reasonURI: "test:verification"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(source, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(source, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        uint256 id = _createRequest(
            AVARequestAllocation.RequestInput(source, address(counter), RESPONSE, PARAMETERS, BURDEN, expiry)
        );
        bytes32 recognisedHistory = keccak256(abi.encode(kernel.getRecognisedState(source)));
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        evidenceRegistry.registerEvidence(evidence);
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(evidenceId, requestPackageId),
            "operator retirement erased business basis"
        );
        _approveRequest(id);
        counter.execute(requestAllocation, id, RESPONSE, PARAMETERS);
        require(counter.effects() == 1 && keccak256(abi.encode(kernel.getRecognisedState(source))) == recognisedHistory);
        require(!authorityMatrix.isAuthorised(SOURCE_ACTOR, APP, ROLE_SOURCE, AVACoreTypes.ACTION_REGISTER_EVIDENCE));
    }

    function _both(TwoApproverAdministrationFixture manager, address target, bytes memory data) private {
        requestVm.prank(FIRST);
        manager.approve(target, data);
        requestVm.prank(SECOND);
        manager.approve(target, data);
    }
}
