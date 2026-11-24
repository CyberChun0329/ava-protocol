// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {IAVAExecutionApprovalPolicy} from "../src/extensions/requests/IAVAExecutionApprovalPolicy.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

interface RetainedAllocationRevertVm {
    function expectRevert(bytes calldata data) external;
}

contract RetainedAllocationTestPolicy is IAVAExecutionApprovalPolicy, RuleModuleIdentity {
    error ExecutionApprovalRejected();

    AVARequestAllocation private immutable allocation;
    bool private immutable rejected;

    constructor(AVARequestAllocation allocation_, bool rejected_) {
        allocation = allocation_;
        rejected = rejected_;
    }

    function validateExecutionApproval(
        IAVARequestPolicy.RequestContext calldata request,
        IAVARequestPolicy.DecisionContext calldata decision
    ) external view {
        if (rejected) revert ExecutionApprovalRejected();
        require(request.requestAllocation == address(allocation), "execution approval host");
        AVARequestAllocation.RequestRecord memory record = allocation.getRequest(request.requestId);
        require(
            record.approvedAt != 0 && record.allocator == decision.actor && !record.consumed,
            "execution approval record"
        );
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(address(allocation), rejected));
    }
}

contract RetainedAllocationTestExecutor {
    function execute(AVARequestAllocation allocation, uint256 id, bytes32 response, bytes32 parameters) external {
        allocation.consume(id, response, parameters, msg.sender);
        allocation.complete(id, keccak256(abi.encode(id, response, parameters)));
    }
}

contract RetainedAllocationTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("retained-allocation.test.app");
    bytes32 private constant RESPONSE = keccak256("retained-allocation.test.response");
    bytes32 private constant PARAMETERS = keccak256("retained-allocation.test.parameters");
    bytes32 private constant BURDEN = keccak256("retained-allocation.test.burden");
    bytes32 private constant OBJECT = keccak256("retained-allocation.test.object");
    bytes32 private constant EXECUTION_APPROVAL = keccak256("ava.extension.request.execution-approval.v1");
    M14PermissiveApplicationModule private application;
    RetainedAllocationTestExecutor private executor;

    function setUp() public {
        application = new M14PermissiveApplicationModule(APP);
        _setUpRequestAllocation(APP, application, OBJECT);
        executor = new RetainedAllocationTestExecutor();
    }

    function testOptedInApprovalSurvivesAllocationPermissionRevocation() public {
        _installExecutionApproval(false);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);

        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.consumed && record.completed, "retained approval did not execute");
        require(record.allocator == ALLOCATOR_ACTOR, "original allocator changed");
    }

    function testRetainedApprovalSurvivesOriginalAllocatorSubjectDeactivation() public {
        _installExecutionApproval(false);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        bytes32 originalAuthority = _authority(ROLE_ALLOCATOR);
        identityRegistry.deactivateSubject(originalAuthority);

        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.consumed && record.completed, "deactivated allocator lost retained approval");
        require(
            record.allocator == ALLOCATOR_ACTOR && record.allocatorAuthorityId == originalAuthority,
            "original allocator identity changed"
        );
    }

    function testRetainedApprovalDoesNotAuthoriseNewApproval() public {
        _installExecutionApproval(false);
        uint256 approvedId = _createRequest(_input(PARAMETERS));
        _approveRequest(approvedId);
        uint256 pendingId = _createRequest(_input(keccak256("retained-allocation.new-parameters")));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);

        _expectRevokedAllocator();
        _approveRequest(pendingId);

        require(requestAllocation.getRequest(pendingId).allocator == address(0), "new approval escaped revocation");
    }

    function testAbsentCapabilityKeepsCurrentAllocatorAuthorityRequired() public {
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);

        _expectRevokedAllocator();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        require(!requestAllocation.getRequest(id).consumed, "request without capability executed");
    }

    function testExecutionApprovalFailureDoesNotFallBackToCurrentAuthority() public {
        _installExecutionApproval(true);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);

        requestVm.expectRevert(RetainedAllocationTestPolicy.ExecutionApprovalRejected.selector);
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        require(!requestAllocation.getRequest(id).consumed, "rejected execution approval consumed");
    }

    function testExecutionApprovalPolicyDoesNotGateCreationOrApproval() public {
        _installExecutionApproval(true);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);

        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        require(record.creator == SOURCE_ACTOR && record.allocator == ALLOCATOR_ACTOR, "approval callback leaked");
        require(record.approvedAt != 0 && !record.consumed, "approval missing");
    }

    function testHistoricalCapabilitySurvivesReceivingPackageSupersession() public {
        _installExecutionApproval(false);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        requestPackageId = _registerRequestPackage(application, 3);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);

        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        require(requestAllocation.getRequest(id).completed, "historical capability was replaced");
    }

    function testNewPackageCapabilityDoesNotReviveOldApproval() public {
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        _installExecutionApproval(false);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);

        _expectRevokedAllocator();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        require(!requestAllocation.getRequest(id).consumed, "new package retroactively changed old approval");
    }

    function testRetainedApprovalStillRequiresLiveSourceWitness() public {
        _installExecutionApproval(false);
        uint256 id = _createRequest(_input(PARAMETERS));
        _approveRequest(id);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));

        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);

        require(!requestAllocation.getRequest(id).consumed, "inactive source witness executed");
    }

    function _expectRevokedAllocator() private {
        RetainedAllocationRevertVm(address(requestVm)).expectRevert(
            abi.encodeWithSelector(
                AVACoreTypes.NotAuthorised.selector, ALLOCATOR_ACTOR, AVACoreTypes.ACTION_RECORD_ALLOCATION
            )
        );
    }

    function _installExecutionApproval(bool rejected) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory core = _coreBindings(application);
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            new AVACoreRulePackageRegistry.ModuleBinding[](core.length + 1);
        for (uint256 i; i < core.length; ++i) bindings[i] = core[i];
        bindings[core.length] =
            _coreBinding(EXECUTION_APPROVAL, address(new RetainedAllocationTestPolicy(requestAllocation, rejected)));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:retained-allocation"
            ),
            requestPackageId,
            bindings
        );
    }

    function _input(bytes32 parameters) private returns (AVARequestAllocation.RequestInput memory input) {
        input.executor = address(executor);
        input.responseClass = RESPONSE;
        input.parametersHash = parameters;
        input.burdenHash = BURDEN;
        input.validUntil = uint64(block.timestamp + 1 days);
        input.recognisedStateId = _createRequestState(
            input.executor, input.responseClass, input.parametersHash, input.burdenHash, input.validUntil
        );
    }
}
