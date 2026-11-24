// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVABoundRequestPolicy} from "../src/extensions/requests/AVABoundRequestPolicy.sol";
import {
    DefaultAVACorePolicyBundle,
    DefaultCoreAllocationPolicyModule
} from "../src/core/modules/DefaultAVACoreRuleModules.sol";

interface RequestPolicyVm {
    function expectRevert() external;
    function prank(address sender) external;
}

contract RequestPolicyTest {
    RequestPolicyVm private constant vm = RequestPolicyVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant APP = keccak256("policy app");
    bytes32 private constant WORKFLOW = keccak256("policy workflow");
    bytes32 private constant RESPONSE = keccak256("policy response");
    bytes32 private constant BURDEN = keccak256("policy burden");
    AVABoundRequestPolicy private policy;

    function setUp() public {
        policy = new AVABoundRequestPolicy(address(this), APP, WORKFLOW, address(this), RESPONSE, BURDEN);
    }

    function testValidExactSupportAndCanonicalDecision() public view {
        (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
        policy.validateResponseSupport(request, witnesses);
        policy.validateRequestAllocation(request, witnesses, _decision());
    }

    function testRejectsWrongExtensionEvenWhenSenderMatchesIt() public {
        (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
        request.requestAllocation = address(0x1234);
        _commit(request, witnesses);
        vm.expectRevert();
        vm.prank(request.requestAllocation);
        policy.validateResponseSupport(request, witnesses);
    }

    function testRejectsCallerImpersonatingCanonicalContext() public {
        (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
        vm.expectRevert();
        vm.prank(address(0x1234));
        policy.validateResponseSupport(request, witnesses);
    }

    function testRejectsWrongAppWorkflowExecutorResponseAndBurden() public {
        for (uint256 i; i < 5; ++i) {
            (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
            if (i == 0) request.appId = keccak256("different");
            if (i == 1) request.workflowKey = keccak256("different");
            if (i == 2) request.executor = address(policy);
            if (i == 3) request.responseClass = keccak256("different");
            if (i == 4) request.burdenHash = keccak256("different");
            _commit(request, witnesses);
            vm.expectRevert();
            policy.validateResponseSupport(request, witnesses);
        }
    }

    function testRejectsMalformedWitnessAndIncompleteContext() public {
        for (uint256 i; i < 16; ++i) {
            (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
            if (i == 0) request.requestId = 0;
            if (i == 1) request.packageId = 0;
            if (i == 2) request.primaryRecognisedStateId = 0;
            if (i == 3) request.parametersHash = bytes32(0);
            if (i == 4) request.validUntil = uint64(block.timestamp);
            if (i == 5) witnesses[0].recognisedStateId++;
            if (i == 6) witnesses[0].transitionId = 0;
            if (i == 7) witnesses[0].governedObjectId = 0;
            if (i == 8) witnesses[0].packageId++;
            if (i == 9) witnesses[0].objectTypeKey = bytes32(0);
            if (i == 10) witnesses[0].subjectId = bytes32(0);
            if (i == 11) witnesses[0].evidenceReceiptId = 0;
            if (i == 12) witnesses[0].scope.claimHash = bytes32(0);
            if (i == 13) witnesses[0].scope.useHash = bytes32(0);
            if (i == 14) witnesses[0].scope.burdenHash = bytes32(0);
            if (i == 15) request.commitment = bytes32(0);
            vm.expectRevert();
            policy.validateResponseSupport(request, witnesses);
        }
    }

    function testDefaultsAndBoundPolicyRejectScopedAndMultipleWitnesses() public {
        IAVARequestPolicy[3] memory policies = [
            IAVARequestPolicy(address(policy)),
            IAVARequestPolicy(address(new DefaultAVACorePolicyBundle())),
            IAVARequestPolicy(address(new DefaultCoreAllocationPolicyModule()))
        ];
        for (uint256 i; i < policies.length; ++i) {
            (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
            policies[i].validateResponseSupport(request, witnesses);
            request.exactCommitment = false;
            vm.expectRevert();
            policies[i].validateResponseSupport(request, witnesses);
            request.exactCommitment = true;
            IAVARequestPolicy.Witness[] memory multiple = new IAVARequestPolicy.Witness[](2);
            multiple[0] = witnesses[0];
            multiple[1] = witnesses[0];
            vm.expectRevert();
            policies[i].validateResponseSupport(request, multiple);
            vm.expectRevert();
            policies[i].validateResponseSupport(request, new IAVARequestPolicy.Witness[](0));
        }
    }

    function testRejectsMissingOrNoncanonicalDecisionFields() public {
        (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses) = _context();
        for (uint256 i; i < 4; ++i) {
            IAVARequestPolicy.DecisionContext memory decision = _decision();
            if (i == 0) decision.roleKey = bytes32(0);
            if (i == 1) decision.authorityId = bytes32(0);
            if (i == 2) decision.actor = address(0);
            if (i == 3) decision.evaluatedAt++;
            vm.expectRevert();
            policy.validateRequestAllocation(request, witnesses, decision);
        }
    }

    function testConstructorRejectsEmptyBindingsAndIdentityBindsConfiguration() public {
        vm.expectRevert();
        new AVABoundRequestPolicy(address(0), APP, WORKFLOW, address(this), RESPONSE, BURDEN);
        vm.expectRevert();
        new AVABoundRequestPolicy(address(this), APP, WORKFLOW, address(0), RESPONSE, BURDEN);
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert();
            new AVABoundRequestPolicy(
                address(this),
                i == 0 ? bytes32(0) : APP,
                i == 1 ? bytes32(0) : WORKFLOW,
                address(this),
                i == 2 ? bytes32(0) : RESPONSE,
                i == 3 ? bytes32(0) : BURDEN
            );
        }
        AVABoundRequestPolicy other =
            new AVABoundRequestPolicy(address(this), APP, WORKFLOW, address(this), RESPONSE, keccak256("other burden"));
        require(policy.moduleIdentityHash() != other.moduleIdentityHash(), "configuration identity");
    }

    function _decision() private view returns (IAVARequestPolicy.DecisionContext memory) {
        return IAVARequestPolicy.DecisionContext(
            keccak256("role"), keccak256("authority"), address(this), uint64(block.timestamp)
        );
    }

    function _context()
        private
        view
        returns (IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses)
    {
        request = IAVARequestPolicy.RequestContext(
            address(this),
            1,
            APP,
            WORKFLOW,
            2,
            3,
            address(this),
            RESPONSE,
            keccak256("parameters"),
            BURDEN,
            uint64(block.timestamp + 1 days),
            bytes32(0),
            true
        );
        witnesses = new IAVARequestPolicy.Witness[](1);
        witnesses[0] = IAVARequestPolicy.Witness(
            3,
            4,
            5,
            2,
            keccak256("object"),
            keccak256("subject"),
            6,
            IAVARequestPolicy.RecognitionScope(bytes32(0), bytes32(0), bytes32(0))
        );
        _commit(request, witnesses);
    }

    function _commit(IAVARequestPolicy.RequestContext memory request, IAVARequestPolicy.Witness[] memory witnesses)
        private
        view
    {
        request.commitment = keccak256(
            abi.encode(
                keccak256("ava.request-allocation.commitment.v1"),
                block.chainid,
                request.requestAllocation,
                request.appId,
                request.executor,
                request.responseClass,
                request.parametersHash,
                request.burdenHash,
                request.validUntil
            )
        );
        witnesses[0].scope =
            IAVARequestPolicy.RecognitionScope(request.commitment, request.responseClass, request.burdenHash);
    }
}
