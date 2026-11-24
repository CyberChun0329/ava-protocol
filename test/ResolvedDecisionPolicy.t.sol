// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARecognisedDecisionPolicy} from "../src/extensions/decisions/AVARecognisedDecisionPolicy.sol";
import {AVAResolvedDecisionPolicy} from "../src/extensions/decisions/AVAResolvedDecisionPolicy.sol";
import {IAVAResolvedDecisionRegistry} from "../src/extensions/decisions/IAVAResolvedDecisionRegistry.sol";
import {IAVADecisionRegistry} from "../src/extensions/decisions/IAVADecisionRegistry.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

/// @dev The declared universe contains two recognitions; each option selects a different one.
contract SeparatedResolvedWitnessPolicy is AVAFiniteDecisionPolicy {
    bytes32 private immutable ALTERNATIVE_KEY;
    bool public broken;
    error ResolverUnavailable();

    constructor(bytes32 app, bytes32 workflow, Option[] memory options)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {
        ALTERNATIVE_KEY = options[1].key;
    }

    function setBroken(bool value) external {
        broken = value;
    }

    function witnessFor(Request calldata, Option calldata option, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        override
        returns (uint256[] memory indices)
    {
        require(eligible.length == 2, "generic declared pool must contain both witnesses");
        if (broken && option.key == ALTERNATIVE_KEY) revert ResolverUnavailable();
        indices = new uint256[](1);
        indices[0] = option.key == ALTERNATIVE_KEY ? 1 : 0;
    }
}

/// @dev Deliberately exposes the callback precondition without a parent Support invocation.
contract ResolvedDecisionRelayPolicy is AVAResolvedDecisionPolicy {
    constructor(IAVAResolvedDecisionRegistry registry) AVAResolvedDecisionPolicy(registry) {}

    function relay(
        IAVARequestPolicy.RequestContext calldata context,
        IAVARequestPolicy.Witness[] calldata witness,
        IAVARequestPolicy.DecisionContext calldata actor
    ) external view {
        IAVAResolvedDecisionRegistry(DECISION_REGISTRY).validateResolvedExecutionDecision(context, witness, actor);
    }
}

/// @dev A host exposing only the original optional decision interface.
contract LegacyDecisionHost is IAVADecisionRegistry {
    address public immutable override REQUEST_ALLOCATION;

    constructor(address requests) {
        REQUEST_ALLOCATION = requests;
    }

    function validateExecutionSupport(IAVARequestPolicy.RequestContext calldata, IAVARequestPolicy.Witness[] calldata)
        external
        pure {}

    function validateExecutionDecision(
        IAVARequestPolicy.RequestContext calldata,
        IAVARequestPolicy.DecisionContext calldata
    ) external pure {}
}

    contract ResolvedDecisionPolicyTest is DecisionSetFixture {
        struct Scenario {
            uint256 genericId;
            uint256 executionId;
            uint256 decisionId;
            IAVARequestPolicy.WitnessInput[] pool;
        }

        function testResolvedPolicyRequiresOptionalHostCapabilityAtInstallation() public {
            LegacyDecisionHost host = new LegacyDecisionHost(address(requestAllocation));
            AVARecognisedDecisionPolicy legacy = new AVARecognisedDecisionPolicy(host);
            require(legacy.REQUEST_ALLOCATION() == address(requestAllocation), "legacy interface rejected");
            requestVm.expectRevert();
            new AVAResolvedDecisionPolicy(IAVAResolvedDecisionRegistry(address(host)));
        }

        function testResolvedCallbackBindsCallerContextWitnessAndActor() public {
            Scenario memory s = _scenario("resolved callback bindings", 1, 1);
            (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory witness) =
                requestAllocation.SUPPORT().resolve(s.executionId);
            IAVARequestPolicy.DecisionContext memory actor = _decisionActor();
            bytes32 beforeProbes = _probeHash(s);

            requestVm.expectRevert();
            registry.validateResolvedExecutionDecision(context, witness, actor);
            requestVm.prank(address(requestAllocation.SUPPORT()));
            requestVm.expectRevert();
            registry.validateResolvedExecutionDecision(context, witness, actor);
            requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
            bridge.validateRequestAllocation(context, witness, actor);

            // Every caller-owned context field must remain the exact stored request context.
            for (uint256 i; i < 13; ++i) {
                IAVARequestPolicy.RequestContext memory foreign = _foreignContext(context, i);
                requestVm.prank(address(bridge));
                requestVm.expectRevert();
                registry.validateResolvedExecutionDecision(foreign, witness, actor);
            }

            IAVARequestPolicy.Witness[] memory forged = abi.decode(abi.encode(witness), (IAVARequestPolicy.Witness[]));
            forged[0].transitionId++;
            requestVm.prank(address(bridge));
            requestVm.expectRevert();
            registry.validateResolvedExecutionDecision(context, forged, actor);
            requestVm.prank(address(requestAllocation.SUPPORT()));
            requestVm.expectRevert();
            bridge.validateRequestAllocation(context, forged, actor);

            IAVARequestPolicy.DecisionContext memory foreignActor = _decisionActor();
            foreignActor.actor = SOURCE_ACTOR;
            requestVm.prank(address(bridge));
            requestVm.expectRevert();
            registry.validateResolvedExecutionDecision(context, witness, foreignActor);
            foreignActor = _decisionActor();
            foreignActor.authorityId = keccak256("foreign allocator authority");
            requestVm.prank(address(bridge));
            requestVm.expectRevert();
            registry.validateResolvedExecutionDecision(context, witness, foreignActor);
            foreignActor = _decisionActor();
            foreignActor.evaluatedAt++;
            requestVm.prank(address(requestAllocation.SUPPORT()));
            requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
            bridge.validateRequestAllocation(context, witness, foreignActor);

            requestVm.prank(address(bridge));
            registry.validateResolvedExecutionDecision(context, witness, actor);
            requestVm.prank(address(requestAllocation.SUPPORT()));
            bridge.validateRequestAllocation(context, witness, actor);
            // Direct Allocation compatibility calls ignore supplied witnesses and freshly resolve Core support.
            requestVm.prank(address(requestAllocation));
            bridge.validateRequestAllocation(context, forged, actor);
            registry.validateExecutionDecision(context, actor);
            authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
            requestVm.prank(address(requestAllocation));
            requestVm.expectRevert();
            bridge.validateRequestAllocation(context, forged, actor);
            requestVm.expectRevert();
            registry.validateExecutionDecision(context, actor);
            authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
            require(_probeHash(s) == beforeProbes, "read-only callbacks changed request or history");
            _executeOnce(s);
        }

        function testLegacyPolicyStillCompletesWithNewRegistry() public {
            bridge = new AVARecognisedDecisionPolicy(registry);
            _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
            Scenario memory s = _scenario("explicit legacy policy", 1, 1);
            (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory witness) =
                requestAllocation.SUPPORT().resolve(s.executionId);
            bytes32 beforeProbes = _probeHash(s);
            requestVm.prank(address(requestAllocation.SUPPORT()));
            bridge.validateResponseSupport(context, witness);
            requestVm.prank(address(requestAllocation.SUPPORT()));
            bridge.validateRequestAllocation(context, new IAVARequestPolicy.Witness[](0), _decisionActor());
            registry.validateExecutionDecision(context, _decisionActor());
            require(_probeHash(s) == beforeProbes, "legacy callback changed request or history");
            _executeOnce(s);
            uint256 evidenceId = kernel.getRecognisedStateReference(s.pool[0].recognisedStateId).evidenceReceiptId;
            requestVm.prank(SOURCE_ACTOR);
            evidenceRegistry.recordEvidenceLifecycle(
                evidenceId,
                ROLE_SOURCE,
                _authority(ROLE_SOURCE),
                AVACoreTypes.EvidenceLifecycleKind.Revoke,
                0,
                REASON,
                "test:retire-legacy-support"
            );
            bytes32 completedBefore = _probeHash(s);
            requestVm.expectRevert();
            registry.validateExecutionDecision(context, _decisionActor());
            requestVm.prank(address(requestAllocation.SUPPORT()));
            requestVm.expectRevert();
            bridge.validateRequestAllocation(context, new IAVARequestPolicy.Witness[](0), _decisionActor());
            require(_probeHash(s) == completedBefore, "fresh support rejection rewrote completed history");
        }

        function testGenericPoolStaysIndependentAndUnselectedFailureRollsBackConsumption() public {
            SeparatedResolvedWitnessPolicy selected =
                new SeparatedResolvedWitnessPolicy(APP, REQUEST_WORKFLOW, _options(2, false, 0));
            _install(selected);
            Scenario memory s = _scenario("generic pair execution singleton", 2, 1);
            require(registry.getSupportRevision(s.genericId, 1).pool.length == 2, "declared universe lost");
            require(registry.getEligibleWitnesses(s.genericId).length == 2, "generic eligible pool lost");
            (, IAVARequestPolicy.Witness[] memory executionWitness) = requestAllocation.SUPPORT().resolve(s.executionId);
            require(
                executionWitness.length == 1 && executionWitness[0].recognisedStateId == s.pool[0].recognisedStateId,
                "execution must contain only the selected first witness"
            );
            require(
                registry.getDecision(s.decisionId).witness.length == 1
                    && registry.getDecision(s.decisionId).witness[0].recognisedStateId == s.pool[0].recognisedStateId,
                "selected decision witness changed"
            );
            bytes32 beforeFailure = _probeHash(s);
            selected.setBroken(true);
            requestVm.expectRevert(SeparatedResolvedWitnessPolicy.ResolverUnavailable.selector);
            requestAllocation.validateExecution(s.executionId, RESPONSE, PARAMETERS, address(executor));
            requestVm.expectRevert(SeparatedResolvedWitnessPolicy.ResolverUnavailable.selector);
            executor.execute(requestAllocation, s.executionId, RESPONSE, PARAMETERS);
            require(_probeHash(s) == beforeFailure, "unselected resolver failure changed approval or history");
            selected.setBroken(false);
            _executeOnce(s);
        }

        function testInstalledRelayCallbackDoesNotGrantExecutionAuthority() public {
            ResolvedDecisionRelayPolicy relay = new ResolvedDecisionRelayPolicy(registry);
            bridge = relay;
            _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
            Scenario memory s = _scenario("installed relay precondition", 1, 1);
            (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory witness) =
                requestAllocation.SUPPORT().resolve(s.executionId);
            bytes32 beforeProbe = _probeHash(s);
            // This public relay is the installed policy, but this call has no parent Support call.
            // A successful view callback therefore authenticates neither an upstream validation nor an executor.
            relay.relay(context, witness, _decisionActor());
            require(_probeHash(s) == beforeProbe, "relay view granted an effect");
            requestVm.expectRevert();
            requestAllocation.consume(s.executionId, RESPONSE, PARAMETERS, address(this));
            requestVm.expectRevert();
            executor.execute(requestAllocation, s.executionId, RESPONSE, keccak256("wrong execution parameters"));
            require(_probeHash(s) == beforeProbe, "relay bypassed executor or exact terms");
            _executeOnce(s);
        }

        function _scenario(bytes32 label, uint256 genericSize, uint256 executionSize)
            private
            returns (Scenario memory s)
        {
            IAVADecisionPolicy.Request memory input = _input(label);
            s.pool = _pool(input, genericSize);
            s.genericId = _open(input, s.pool);
            IAVARequestPolicy.WitnessInput[] memory executionPool = new IAVARequestPolicy.WitnessInput[](executionSize);
            for (uint256 i; i < executionSize; ++i) {
                executionPool[i] = s.pool[i];
            }
            s.executionId = _execution(input, executionPool, PARAMETERS);
            s.decisionId = _choose(s.genericId, POSITIVE, s.executionId, 0);
        }

        function _decisionActor() private view returns (IAVARequestPolicy.DecisionContext memory) {
            return IAVARequestPolicy.DecisionContext(
                ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), ALLOCATOR_ACTOR, uint64(block.timestamp)
            );
        }

        function _foreignContext(IAVARequestPolicy.RequestContext memory context, uint256 field)
            private
            pure
            returns (IAVARequestPolicy.RequestContext memory changed)
        {
            changed = abi.decode(abi.encode(context), (IAVARequestPolicy.RequestContext));
            if (field == 0) changed.requestAllocation = address(0xBAD);
            else if (field == 1) changed.requestId += 1_000;
            else if (field == 2) changed.appId = keccak256("foreign app");
            else if (field == 3) changed.workflowKey = keccak256("foreign workflow");
            else if (field == 4) changed.packageId += 1_000;
            else if (field == 5) changed.primaryRecognisedStateId += 1_000;
            else if (field == 6) changed.executor = address(0xBAD);
            else if (field == 7) changed.responseClass = keccak256("foreign response");
            else if (field == 8) changed.parametersHash = keccak256("foreign parameters");
            else if (field == 9) changed.burdenHash = keccak256("foreign burden");
            else if (field == 10) changed.validUntil++;
            else if (field == 11) changed.commitment = keccak256("foreign commitment");
            else changed.exactCommitment = !changed.exactCommitment;
        }

        function _probeHash(Scenario memory s) private view returns (bytes32) {
            return keccak256(abi.encode(requestAllocation.getRequest(s.executionId), _historyHash(s)));
        }

        function _historyHash(Scenario memory s) private view returns (bytes32) {
            bytes32[] memory sourceHashes = new bytes32[](s.pool.length);
            for (uint256 i; i < s.pool.length; ++i) {
                sourceHashes[i] = keccak256(abi.encode(kernel.getRecognisedState(s.pool[i].recognisedStateId)));
            }
            return keccak256(
                abi.encode(
                    registry.getRequest(s.genericId),
                    registry.getDecision(s.decisionId),
                    registry.getSupportRevision(s.genericId, 1),
                    sourceHashes,
                    registry.nextDecisionId(),
                    requestAllocation.nextRequestId(),
                    kernel.nextTransitionId()
                )
            );
        }

        function _executeOnce(Scenario memory s) private {
            bytes32 historyBefore = _historyHash(s);
            executor.execute(requestAllocation, s.executionId, RESPONSE, PARAMETERS);
            AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(s.executionId);
            require(
                completed.consumed && completed.completed && completed.effectHash != bytes32(0)
                    && completed.allocator == ALLOCATOR_ACTOR,
                "lawful effect missing"
            );
            require(_historyHash(s) == historyBefore, "execution changed recognition or decision history");
            requestVm.expectRevert();
            executor.execute(requestAllocation, s.executionId, RESPONSE, PARAMETERS);
            require(
                keccak256(abi.encode(requestAllocation.getRequest(s.executionId))) == keccak256(abi.encode(completed))
                    && _historyHash(s) == historyBefore,
                "repeat effect changed completed history"
            );
        }
    }
