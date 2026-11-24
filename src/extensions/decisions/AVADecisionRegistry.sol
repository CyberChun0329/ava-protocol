// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACapabilityKeys} from "../../core/AVACapabilityKeys.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../../core/interfaces/IAVADecisionPolicy.sol";
import {IAVAProcedurePolicy} from "../../core/interfaces/IAVAProcedurePolicy.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {IAVACorrectionReview} from "../../core/interfaces/IAVACorrectionReview.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";
import {AVARequestAllocation} from "../requests/AVARequestAllocation.sol";
import {IAVAResolvedDecisionRegistry} from "./IAVAResolvedDecisionRegistry.sol";
import {AVADecisionWitnessValidation} from "./AVADecisionWitnessValidation.sol";

/// @notice Request intake, the full admissible correspondence, and explicit decisions.
/// @dev Recognition remains exclusively in Core. The declared pool bounds the domain search.
contract AVADecisionRegistry is IAVAResolvedDecisionRegistry, RuleModuleIdentity {
    bytes4 public constant override RESOLVED_DECISION_CALLBACK =
        IAVAResolvedDecisionRegistry.validateResolvedExecutionDecision.selector;
    bytes32 public constant ACTION_OPEN_REQUEST = keccak256("ava.extension.decision.request.open.v1");
    bytes32 public constant ACTION_UPDATE_SUPPORT = keccak256("ava.extension.decision.support.update.v1");
    uint256 public constant MAX_POOL = 16;
    uint256 public constant MAX_OPTIONS = 32;

    bytes32 public constant ACTION_FILE_PROCEDURE_CHALLENGE = keccak256("ava.extension.procedure.challenge.file.v1");
    bytes32 public constant ACTION_RESOLVE_PROCEDURE_CHALLENGE =
        keccak256("ava.extension.procedure.challenge.resolve.v1");

    struct ProcedureSnapshot {
        bool paused;
        bool closed;
    }

    struct ProcedureApplication {
        uint256 decisionId;
        uint256 expectedCurrentDecisionId;
        uint256 resolutionId;
        IAVAProcedurePolicy.Outcome outcome;
        bytes32 replacementKey;
        address resolver;
        bytes32 roleKey;
        bytes32 authorityId;
        bytes32 reasonHash;
    }
    mapping(uint256 => ProcedureSnapshot) private procedureBefore;
    mapping(uint256 => uint256) public procedureDisposition;
    mapping(uint256 => uint256) public procedureReviewIdByDecision;
    mapping(uint256 => uint256) public constitutionalReviewIdByDecision;

    struct AtomicRequest {
        uint256 id;
        IAVADecisionPolicy.Request input;
        address creator;
        bytes32 creatorRoleKey;
        bytes32 creatorAuthorityId;
        uint64 createdAt;
        uint256 supportRevision;
        uint256 lastDecisionId;
        uint256 allocationDecisionId;
        bool paused;
        bool closed;
    }

    struct SupportRevision {
        uint256 revision;
        bytes32 revisionHash;
        bytes32 previousHash;
        address updatedBy;
        bytes32 roleKey;
        bytes32 authorityId;
        uint64 updatedAt;
        IAVARequestPolicy.WitnessInput[] pool;
    }

    struct DecisionRecord {
        uint256 id;
        uint256 requestId;
        IAVADecisionPolicy.Option option;
        address actor;
        bytes32 roleKey;
        bytes32 authorityId;
        uint64 evaluatedAt;
        bytes32 reasonHash;
        uint256 previousDecisionId;
        uint256 supportRevision;
        bytes32 witnessHash;
        IAVARequestPolicy.Witness[] witness;
        uint256 executionRequestId;
    }

    struct Evaluation {
        IAVADecisionPolicy.Option[] admissible;
        IAVARequestPolicy.Witness[] selectedWitness;
    }

    enum AuthorityResult {
        Unchecked,
        Denied,
        Granted
    }

    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    address public immutable override REQUEST_ALLOCATION;
    mapping(uint256 => AtomicRequest) private requests;
    mapping(uint256 => mapping(uint256 => SupportRevision)) private supportRevisions;
    mapping(uint256 => DecisionRecord) private decisions;
    mapping(bytes32 => uint256) public requestIdByHash;
    uint256 public nextRequestId = 1;
    uint256 public nextDecisionId = 1;

    event RequestOpened(uint256 indexed requestId, bytes32 indexed requestHash, address indexed creator);
    event SupportUpdated(uint256 indexed requestId, uint256 indexed revision, bytes32 revisionHash);
    event DecisionChosen(uint256 indexed decisionId, uint256 indexed requestId, bytes32 indexed optionKey);

    constructor(AVAGovernanceKernel kernel, AVARequestAllocation requestAllocation) {
        if (address(kernel).code.length == 0 || address(requestAllocation).code.length == 0) {
            revert AVACoreTypes.EmptyValue();
        }
        if (
            address(requestAllocation.GOVERNANCE_KERNEL()) != address(kernel)
                || address(requestAllocation.AUTHORITY_MATRIX()) != address(kernel.AUTHORITY_MATRIX())
                || address(requestAllocation.IDENTITY_REGISTRY()) != address(kernel.IDENTITY_REGISTRY())
                || address(requestAllocation.RULE_PACKAGE_REGISTRY()) != address(kernel.RULE_PACKAGE_REGISTRY())
                || address(requestAllocation.EVIDENCE_REGISTRY()) != address(kernel.EVIDENCE_REGISTRY())
                || address(requestAllocation.SUPPORT().GOVERNANCE_KERNEL()) != address(kernel)
                || requestAllocation.SUPPORT().REQUEST_ALLOCATION() != address(requestAllocation)
        ) revert AVACoreTypes.InvalidState(0);
        GOVERNANCE_KERNEL = kernel;
        REQUEST_ALLOCATION = address(requestAllocation);
    }

    function openRequest(
        IAVADecisionPolicy.Request calldata input,
        IAVARequestPolicy.WitnessInput[] calldata declaredPool,
        bytes32 roleKey,
        bytes32 authorityId
    ) external returns (uint256 id) {
        if (
            input.appId == bytes32(0) || input.workflowKey == bytes32(0) || input.packageId == 0
                || input.requestHash == bytes32(0) || input.executor.code.length == 0
                || input.responseClass == bytes32(0) || input.burdenHash == bytes32(0)
                || input.validUntil <= block.timestamp
        ) revert AVACoreTypes.EmptyValue();
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(msg.sender, input.appId, roleKey, ACTION_OPEN_REQUEST, authorityId);
        _policy(input);
        if (
            GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getActivePackageId(input.appId, input.workflowKey)
                != input.packageId
        ) revert AVACoreTypes.InvalidState(input.packageId);
        bytes32 hashKey = _requestHashKey(input.appId, input.workflowKey, input.requestHash);
        if (requestIdByHash[hashKey] != 0) revert AVACoreTypes.InvalidState(requestIdByHash[hashKey]);
        id = nextRequestId++;
        AtomicRequest storage record = requests[id];
        record.id = id;
        record.input = input;
        record.creator = msg.sender;
        record.creatorRoleKey = roleKey;
        record.creatorAuthorityId = authorityId;
        record.createdAt = uint64(block.timestamp);
        requestIdByHash[hashKey] = id;
        _storeSupport(record, declaredPool, roleKey, authorityId);
        emit RequestOpened(id, input.requestHash, msg.sender);
    }

    function updateSupport(
        uint256 requestId,
        IAVARequestPolicy.WitnessInput[] calldata declaredPool,
        uint256 expectedRevision,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        AtomicRequest storage record = _request(requestId);
        if (record.supportRevision != expectedRevision || record.closed) revert AVACoreTypes.InvalidState(requestId);
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(msg.sender, record.input.appId, roleKey, ACTION_UPDATE_SUPPORT, authorityId);
        _policy(record.input);
        _storeSupport(record, declaredPool, roleKey, authorityId);
    }

    function getRequest(uint256 id) external view returns (AtomicRequest memory) {
        return _request(id);
    }

    function getSupportRevision(uint256 id, uint256 revision) external view returns (SupportRevision memory) {
        _request(id);
        if (revision == 0 || revision > requests[id].supportRevision) revert AVACoreTypes.UnknownReference(revision);
        return supportRevisions[id][revision];
    }

    function getDecision(uint256 id) external view returns (DecisionRecord memory) {
        if (decisions[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return decisions[id];
    }

    function getEligibleWitnesses(uint256 id) external view returns (IAVARequestPolicy.Witness[] memory) {
        return _eligible(_request(id));
    }

    function getAdmissibleDecisions(uint256 id, address actor, bytes32 roleKey, bytes32 authorityId)
        public
        view
        returns (IAVADecisionPolicy.Option[] memory admissible)
    {
        return _evaluate(
            _request(id), IAVADecisionPolicy.Actor(actor, roleKey, authorityId, uint64(block.timestamp)), bytes32(0)
        )
        .admissible;
    }

    /// @dev Evaluation is read-only. Keep the chosen witness from the same complete catalogue pass.
    function _evaluate(AtomicRequest storage record, IAVADecisionPolicy.Actor memory decisionActor, bytes32 selectedKey)
        private
        view
        returns (Evaluation memory evaluation)
    {
        IAVADecisionPolicy policy = _policy(record.input);
        IAVADecisionPolicy.Option[] memory catalogue = _catalogue(policy, record.input);
        IAVARequestPolicy.Witness[] memory eligible = _eligible(record);
        IAVADecisionPolicy.Process memory process = _process(record);
        bool valid = policy.ruleValid(record.input, uint64(block.timestamp));
        IAVADecisionPolicy.Option[] memory admissible = new IAVADecisionPolicy.Option[](catalogue.length);
        uint256 count;
        AuthorityResult allocationAuthority;
        for (uint256 i; i < catalogue.length; ++i) {
            IAVADecisionPolicy.Option memory option = catalogue[i];
            // Validate every substantive resolver even when authority/process later excludes it.
            IAVARequestPolicy.Witness[] memory witness = _witness(policy, record.input, option, eligible);
            bool allowed = policy.allocationAllowed(record.input, process, decisionActor, option);
            bool substantive = option.kind == IAVADecisionPolicy.Kind.Substantive;
            bool authorised;
            if (valid && allowed) {
                // _catalogue requires the same allocation action for every substantive option.
                // All calls in this evaluation are read-only; later evaluations recheck authority.
                if (substantive && allocationAuthority != AuthorityResult.Unchecked) {
                    authorised = allocationAuthority == AuthorityResult.Granted;
                } else {
                    authorised = _authorised(record.input.appId, decisionActor, option.actionKey);
                    if (substantive) {
                        allocationAuthority = authorised ? AuthorityResult.Granted : AuthorityResult.Denied;
                    }
                }
            }
            if (authorised && _intrinsic(record, option) && (!substantive || witness.length != 0)) {
                admissible[count++] = option;
                if (option.key == selectedKey) evaluation.selectedWitness = witness;
            }
        }
        assembly ("memory-safe") {
            mstore(admissible, count)
        }
        evaluation.admissible = admissible;
    }

    function choose(
        uint256 requestId,
        bytes32 optionKey,
        uint256 executionRequestId,
        uint256 expectedPreviousDecisionId,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 reasonHash
    ) external returns (uint256 id) {
        AtomicRequest storage record = _request(requestId);
        if (record.lastDecisionId != expectedPreviousDecisionId || reasonHash == bytes32(0)) {
            revert AVACoreTypes.InvalidState(requestId);
        }
        Evaluation memory evaluation = _evaluate(
            record, IAVADecisionPolicy.Actor(msg.sender, roleKey, authorityId, uint64(block.timestamp)), optionKey
        );
        IAVADecisionPolicy.Option[] memory admissible = evaluation.admissible;
        IAVADecisionPolicy.Option memory option;
        bool found;
        for (uint256 i; i < admissible.length; ++i) {
            if (admissible[i].key == optionKey) {
                option = admissible[i];
                found = true;
                break;
            }
        }
        if (!found) revert AVACoreTypes.InvalidState(requestId);
        IAVARequestPolicy.Witness[] memory witness = evaluation.selectedWitness;
        if (option.kind == IAVADecisionPolicy.Kind.Substantive) {
            if (executionRequestId == 0) revert AVACoreTypes.EmptyValue();
            _requireExecutionRequest(record, option, executionRequestId, witness);
        } else {
            if (executionRequestId != 0) revert AVACoreTypes.InvalidState(executionRequestId);
            witness = new IAVARequestPolicy.Witness[](0);
        }
        id = nextDecisionId++;
        DecisionRecord storage decision = decisions[id];
        decision.id = id;
        decision.requestId = requestId;
        decision.option = option;
        decision.actor = msg.sender;
        decision.roleKey = roleKey;
        decision.authorityId = authorityId;
        decision.evaluatedAt = uint64(block.timestamp);
        decision.reasonHash = reasonHash;
        decision.previousDecisionId = record.lastDecisionId;
        decision.supportRevision = record.supportRevision;
        decision.witnessHash = keccak256(abi.encode(witness));
        decision.executionRequestId = executionRequestId;
        for (uint256 i; i < witness.length; ++i) {
            decision.witness.push(witness[i]);
        }
        record.lastDecisionId = id;
        if (option.kind != IAVADecisionPolicy.Kind.Substantive) {
            procedureBefore[id] = ProcedureSnapshot(record.paused, record.closed);
            _applyProcedure(record, option.kind);
        }
        if (option.kind == IAVADecisionPolicy.Kind.Substantive) {
            record.allocationDecisionId = id;
            AVARequestAllocation(REQUEST_ALLOCATION)
                .approveFromDecision(executionRequestId, roleKey, authorityId, msg.sender);
        }
        emit DecisionChosen(id, requestId, option.key);
    }

    function isProcedureCurrent(uint256 decisionId) external view returns (bool) {
        DecisionRecord storage target = decisions[decisionId];
        if (target.id == 0) revert AVACoreTypes.UnknownReference(decisionId);
        return target.option.kind != IAVADecisionPolicy.Kind.Substantive
            && requests[target.requestId].lastDecisionId == decisionId && procedureDisposition[decisionId] == 0;
    }

    /// @notice Apply only the Core's active, separately authorised withdrawal of this procedural decision.
    function applyCorrectionReviewWithdrawal(uint256 decisionId, uint256 reviewId) external {
        IAVACorrectionReview corrections = IAVACorrectionReview(address(GOVERNANCE_KERNEL.CORRECTIONS()));
        DecisionRecord storage target = decisions[decisionId];
        if (target.id == 0) revert AVACoreTypes.UnknownReference(decisionId);
        AtomicRequest storage record = _request(target.requestId);
        corrections.requireActiveProcedureWithdrawal(
            reviewId, msg.sender, decisionId, record.input.appId, record.input.workflowKey, record.input.packageId
        );
        if (
            target.option.kind == IAVADecisionPolicy.Kind.Substantive || record.lastDecisionId != decisionId
                || procedureDisposition[decisionId] != 0
        ) revert AVACoreTypes.InvalidState(decisionId);
        ProcedureSnapshot memory beforeState = procedureBefore[decisionId];
        record.paused = beforeState.paused;
        record.closed = beforeState.closed;
        procedureDisposition[decisionId] = reviewId;
        constitutionalReviewIdByDecision[decisionId] = reviewId;
    }

    /// @notice Only the historical package's fixed review module may apply a separately adjudicated correction.
    function applyProcedureReview(ProcedureApplication calldata input) external returns (uint256 replacementId) {
        DecisionRecord storage target = decisions[input.decisionId];
        if (target.id == 0) revert AVACoreTypes.UnknownReference(input.decisionId);
        AtomicRequest storage record = _request(target.requestId);
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.PROCEDURE_REVIEW;
        (, address[] memory modules) =
            GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getVerifiedModulesCompact(record.input.packageId, keys);
        if (msg.sender != modules[0] || modules[0] == address(0)) {
            revert AVACoreTypes.NotAuthorised(msg.sender, ACTION_RESOLVE_PROCEDURE_CHALLENGE);
        }
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                input.resolver, record.input.appId, input.roleKey, ACTION_RESOLVE_PROCEDURE_CHALLENGE, input.authorityId
            );
        if (
            target.option.kind == IAVADecisionPolicy.Kind.Substantive
                || record.lastDecisionId != input.expectedCurrentDecisionId || record.lastDecisionId != target.id
                || procedureDisposition[target.id] != 0 || input.resolutionId == 0 || input.reasonHash == bytes32(0)
                || (input.outcome != IAVAProcedurePolicy.Outcome.Withdrawn
                    && input.outcome != IAVAProcedurePolicy.Outcome.Replaced)
        ) {
            revert AVACoreTypes.InvalidState(input.decisionId);
        }
        procedureDisposition[target.id] = input.resolutionId;
        ProcedureSnapshot memory beforeState = procedureBefore[target.id];
        record.paused = beforeState.paused;
        record.closed = beforeState.closed;
        if (input.outcome == IAVAProcedurePolicy.Outcome.Withdrawn) {
            if (input.replacementKey != bytes32(0)) revert AVACoreTypes.InvalidState(input.decisionId);
            return 0;
        }
        IAVADecisionPolicy policy = _policy(record.input);
        IAVADecisionPolicy.Option[] memory options = _catalogue(policy, record.input);
        IAVADecisionPolicy.Actor memory actor =
            IAVADecisionPolicy.Actor(input.resolver, input.roleKey, input.authorityId, uint64(block.timestamp));
        for (uint256 i; i < options.length; ++i) {
            if (options[i].key != input.replacementKey || options[i].kind == IAVADecisionPolicy.Kind.Substantive) {
                continue;
            }
            if (
                !_authorised(record.input.appId, actor, options[i].actionKey)
                    || !policy.allocationAllowed(record.input, _process(record), actor, options[i])
            ) revert AVACoreTypes.InvalidState(target.id);
            replacementId = nextDecisionId++;
            DecisionRecord storage replacement = decisions[replacementId];
            replacement.id = replacementId;
            replacement.requestId = record.id;
            replacement.option = options[i];
            replacement.actor = input.resolver;
            replacement.roleKey = input.roleKey;
            replacement.authorityId = input.authorityId;
            replacement.evaluatedAt = uint64(block.timestamp);
            replacement.reasonHash = input.reasonHash;
            replacement.previousDecisionId = record.lastDecisionId;
            replacement.supportRevision = record.supportRevision;
            replacement.witnessHash = keccak256(abi.encode(new IAVARequestPolicy.Witness[](0)));
            procedureBefore[replacementId] = ProcedureSnapshot(record.paused, record.closed);
            procedureReviewIdByDecision[replacementId] = input.resolutionId;
            record.lastDecisionId = replacementId;
            _applyProcedure(record, options[i].kind);
            emit DecisionChosen(replacementId, record.id, options[i].key);
            return replacementId;
        }
        revert AVACoreTypes.InvalidState(target.id);
    }

    function _applyProcedure(AtomicRequest storage record, IAVADecisionPolicy.Kind kind) private {
        if (kind == IAVADecisionPolicy.Kind.Close) record.closed = true;
        else if (kind == IAVADecisionPolicy.Kind.Resume) record.paused = false;
        else record.paused = true;
    }

    function validateExecutionSupport(
        IAVARequestPolicy.RequestContext calldata context,
        IAVARequestPolicy.Witness[] calldata witness
    ) external view override {
        AtomicRequest storage record = _executionAtomicRequest(context, witness);
        IAVADecisionPolicy policy = _policy(record.input);
        IAVADecisionPolicy.Option[] memory catalogue = _catalogue(policy, record.input);
        if (!policy.ruleValid(record.input, uint64(block.timestamp))) revert AVACoreTypes.InvalidState(record.id);
        IAVARequestPolicy.Witness[] memory eligible = _eligible(record);
        bytes32 witnessHash = keccak256(abi.encode(witness));
        bool found;
        for (uint256 i; i < catalogue.length; ++i) {
            IAVARequestPolicy.Witness[] memory selected = _witness(policy, record.input, catalogue[i], eligible);
            if (
                catalogue[i].kind == IAVADecisionPolicy.Kind.Substantive
                    && catalogue[i].parametersHash == context.parametersHash && selected.length != 0
                    && keccak256(abi.encode(selected)) == witnessHash
            ) found = true;
        }
        if (!found) revert AVACoreTypes.InvalidState(record.id);
    }

    function validateExecutionDecision(
        IAVARequestPolicy.RequestContext calldata context,
        IAVARequestPolicy.DecisionContext calldata actor
    ) external view override {
        (, IAVARequestPolicy.Witness[] memory witness) =
            AVARequestAllocation(REQUEST_ALLOCATION).SUPPORT().resolve(context.requestId);
        _validateExecutionDecision(context, witness, actor);
    }

    /// @notice Policy callback after canonical Support has resolved execution witnesses.
    /// @dev Caller/context binding is not proof of a parent Support call. This read-only path
    /// does not replace Core validation or the standalone fresh-resolution entry above.
    function validateResolvedExecutionDecision(
        IAVARequestPolicy.RequestContext calldata context,
        IAVARequestPolicy.Witness[] calldata witness,
        IAVARequestPolicy.DecisionContext calldata actor
    ) external view override {
        AVADecisionWitnessValidation.requireResolvedCallback(GOVERNANCE_KERNEL, REQUEST_ALLOCATION, context);
        _validateExecutionDecision(context, witness, actor);
    }

    function _validateExecutionDecision(
        IAVARequestPolicy.RequestContext memory context,
        IAVARequestPolicy.Witness[] memory witness,
        IAVARequestPolicy.DecisionContext memory actor
    ) private view {
        AtomicRequest storage record = _executionAtomicRequest(context, witness);
        DecisionRecord storage selected = decisions[record.allocationDecisionId];
        if (
            selected.id == 0 || selected.executionRequestId != context.requestId || record.paused || record.closed
                || block.timestamp >= record.input.validUntil || selected.actor != actor.actor
                || selected.roleKey != actor.roleKey || selected.authorityId != actor.authorityId
                || actor.evaluatedAt != block.timestamp || selected.option.parametersHash != context.parametersHash
                || selected.witnessHash != keccak256(abi.encode(witness))
        ) revert AVACoreTypes.InvalidState(context.requestId);
        IAVADecisionPolicy policy = _policy(record.input);
        IAVADecisionPolicy.Option[] memory catalogue = _catalogue(policy, record.input);
        bytes32 optionHash = keccak256(abi.encode(selected.option));
        bool optionFound;
        for (uint256 i; i < catalogue.length; ++i) {
            if (keccak256(abi.encode(catalogue[i])) == optionHash) optionFound = true;
        }
        IAVADecisionPolicy.Actor memory decisionActor =
            IAVADecisionPolicy.Actor(actor.actor, actor.roleKey, actor.authorityId, uint64(block.timestamp));
        if (
            !optionFound || !policy.ruleValid(record.input, uint64(block.timestamp))
                || !_authorised(record.input.appId, decisionActor, selected.option.actionKey)
                || !policy.allocationAllowed(record.input, _process(record), decisionActor, selected.option)
                || selected.witnessHash
                    != keccak256(abi.encode(_witness(policy, record.input, selected.option, _eligible(record))))
        ) revert AVACoreTypes.InvalidState(context.requestId);
        // The original request path sets allocator after the approval callback. Consumption has it set.
        if (
            AVARequestAllocation(REQUEST_ALLOCATION).getRequest(context.requestId).allocator != address(0)
                && block.timestamp < selected.option.notBefore
        ) revert AVACoreTypes.InvalidState(context.requestId);
    }

    function _storeSupport(
        AtomicRequest storage record,
        IAVARequestPolicy.WitnessInput[] calldata pool,
        bytes32 roleKey,
        bytes32 authorityId
    ) private {
        if (pool.length > MAX_POOL) revert AVACoreTypes.EmptyValue();
        if (pool.length > 1) {
            if (address(AVADecisionWitnessValidation).code.length == 0) {
                revert AVACoreTypes.InvalidState(pool[0].recognisedStateId);
            }
            AVADecisionWitnessValidation.validateAdmission(GOVERNANCE_KERNEL, record.input, pool);
        } else if (pool.length == 1) {
            // Keep singleton admission on its original fresh-resolution path.
            if (pool[0].recognisedStateId == 0) revert AVACoreTypes.InvalidState(0);
            (, bool eligible) = _resolve(record.input, pool[0]);
            if (!eligible) revert AVACoreTypes.InvalidState(pool[0].recognisedStateId);
        }
        bytes32 previousHash = supportRevisions[record.id][record.supportRevision].revisionHash;
        uint256 revision = ++record.supportRevision;
        SupportRevision storage stored = supportRevisions[record.id][revision];
        stored.revision = revision;
        stored.previousHash = previousHash;
        stored.revisionHash = keccak256(
            abi.encode(
                keccak256("ava.decision.support-revision.v1"),
                block.chainid,
                address(this),
                record.id,
                revision,
                previousHash,
                pool
            )
        );
        stored.updatedBy = msg.sender;
        stored.roleKey = roleKey;
        stored.authorityId = authorityId;
        stored.updatedAt = uint64(block.timestamp);
        for (uint256 i; i < pool.length; ++i) {
            stored.pool.push(pool[i]);
        }
        emit SupportUpdated(record.id, revision, stored.revisionHash);
    }

    function _eligible(AtomicRequest storage record) private view returns (IAVARequestPolicy.Witness[] memory result) {
        IAVARequestPolicy.WitnessInput[] storage pool = supportRevisions[record.id][record.supportRevision].pool;
        if (pool.length == 0) return new IAVARequestPolicy.Witness[](0);
        if (pool.length == 1) {
            // There is no repeated package to eliminate in the common singleton case.
            result = new IAVARequestPolicy.Witness[](1);
            (IAVARequestPolicy.Witness memory witness, bool eligible) = _resolve(record.input, pool[0]);
            if (eligible) {
                result[0] = witness;
            } else {
                assembly ("memory-safe") {
                    mstore(result, 0)
                }
            }
            return result;
        }
        if (address(AVADecisionWitnessValidation).code.length == 0) {
            revert AVACoreTypes.InvalidState(pool[0].recognisedStateId);
        }
        return AVADecisionWitnessValidation.resolveEligible(GOVERNANCE_KERNEL, record.input, pool);
    }

    function _resolve(IAVADecisionPolicy.Request memory request, IAVARequestPolicy.WitnessInput memory input)
        private
        view
        returns (IAVARequestPolicy.Witness memory witness, bool eligible)
    {
        if (address(AVADecisionWitnessValidation).code.length == 0) {
            revert AVACoreTypes.InvalidState(input.recognisedStateId);
        }
        return AVADecisionWitnessValidation.resolve(GOVERNANCE_KERNEL, request, input);
    }

    function _policy(IAVADecisionPolicy.Request memory request) private view returns (IAVADecisionPolicy policy) {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.DECISION_SET;
        (AVACoreRulePackageRegistry.VerifiedPackageContext memory context, address[] memory modules) =
            GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getVerifiedModulesCompact(request.packageId, keys);
        if (context.appId != request.appId || context.workflowKey != request.workflowKey || modules[0] == address(0)) {
            revert AVACoreTypes.InvalidState(request.packageId);
        }
        policy = IAVADecisionPolicy(modules[0]);
    }

    function _catalogue(IAVADecisionPolicy policy, IAVADecisionPolicy.Request memory request)
        private
        view
        returns (IAVADecisionPolicy.Option[] memory options)
    {
        options = policy.catalogue(request);
        if (options.length > MAX_OPTIONS) revert AVACoreTypes.InvalidState(request.packageId);
        for (uint256 i; i < options.length; ++i) {
            if (
                options[i].key == bytes32(0) || options[i].actionKey == bytes32(0)
                    || options[i].parametersHash == bytes32(0)
                    || (options[i].kind == IAVADecisionPolicy.Kind.Substantive
                        && options[i].actionKey != AVACoreTypes.ACTION_RECORD_ALLOCATION)
            ) revert AVACoreTypes.InvalidState(request.packageId);
            for (uint256 j; j < i; ++j) {
                if (options[i].key == options[j].key) {
                    revert AVACoreTypes.InvalidState(request.packageId);
                }
            }
        }
    }

    function _witness(
        IAVADecisionPolicy policy,
        IAVADecisionPolicy.Request memory request,
        IAVADecisionPolicy.Option memory option,
        IAVARequestPolicy.Witness[] memory eligible
    ) private view returns (IAVARequestPolicy.Witness[] memory selected) {
        if (option.kind != IAVADecisionPolicy.Kind.Substantive) return new IAVARequestPolicy.Witness[](0);
        uint256[] memory indices = policy.witnessFor(request, option, eligible);
        selected = new IAVARequestPolicy.Witness[](indices.length);
        for (uint256 i; i < indices.length; ++i) {
            if (indices[i] >= eligible.length || (i != 0 && indices[i] <= indices[i - 1])) {
                revert AVACoreTypes.InvalidState(request.packageId);
            }
            selected[i] = eligible[indices[i]];
        }
    }

    function _authorised(bytes32 appId, IAVADecisionPolicy.Actor memory actor, bytes32 actionKey)
        private
        view
        returns (bool)
    {
        return GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .isAuthorisedSubject(actor.account, appId, actor.roleKey, actionKey, actor.authorityId);
    }

    function _intrinsic(AtomicRequest storage record, IAVADecisionPolicy.Option memory option)
        private
        view
        returns (bool)
    {
        if (record.closed || block.timestamp >= record.input.validUntil) return false;
        if (option.kind != IAVADecisionPolicy.Kind.Substantive) {
            return option.kind != IAVADecisionPolicy.Kind.Resume || record.paused;
        }
        if (record.paused) return false;
        bytes32 meaning = keccak256(
            abi.encode(
                block.chainid,
                REQUEST_ALLOCATION,
                record.input.appId,
                record.input.executor,
                record.input.responseClass,
                option.parametersHash
            )
        );
        if (AVARequestAllocation(REQUEST_ALLOCATION).consumedRequestIdByMeaning(meaning) != 0) return false;
        if (record.allocationDecisionId == 0) return true;
        uint256 executionId = decisions[record.allocationDecisionId].executionRequestId;
        AVARequestAllocation execution = AVARequestAllocation(REQUEST_ALLOCATION);
        return
            !execution.getRequest(executionId).consumed && execution.withdrawalResolutionIdByRequest(executionId) != 0;
    }

    function _process(AtomicRequest storage record) private view returns (IAVADecisionPolicy.Process memory) {
        return IAVADecisionPolicy.Process(
            record.id,
            record.lastDecisionId,
            record.allocationDecisionId,
            decisions[record.allocationDecisionId].executionRequestId,
            record.supportRevision,
            record.paused,
            record.closed
        );
    }

    function _requireExecutionRequest(
        AtomicRequest storage record,
        IAVADecisionPolicy.Option memory option,
        uint256 executionId,
        IAVARequestPolicy.Witness[] memory selected
    ) private view {
        AVARequestAllocation execution = AVARequestAllocation(REQUEST_ALLOCATION);
        AVARequestAllocation.RequestRecord memory actual = execution.getRequest(executionId);
        if (
            actual.creator != record.creator || actual.allocator != address(0) || actual.cancelled || actual.consumed
                || !execution.scopedSupportByRequest(executionId) || actual.appId != record.input.appId
                || actual.workflowKey != record.input.workflowKey || actual.packageId != record.input.packageId
                || actual.input.executor != record.input.executor
                || actual.input.responseClass != record.input.responseClass
                || actual.input.parametersHash != option.parametersHash
                || actual.input.burdenHash != record.input.burdenHash
                || actual.input.validUntil != record.input.validUntil
        ) revert AVACoreTypes.InvalidState(executionId);
        (, IAVARequestPolicy.Witness[] memory actualWitness) = execution.SUPPORT().resolve(executionId);
        if (selected.length == 0 || keccak256(abi.encode(actualWitness)) != keccak256(abi.encode(selected))) {
            revert AVACoreTypes.InvalidState(executionId);
        }
    }

    function _executionAtomicRequest(
        IAVARequestPolicy.RequestContext memory context,
        IAVARequestPolicy.Witness[] memory witness
    ) private view returns (AtomicRequest storage record) {
        if (context.requestAllocation != REQUEST_ALLOCATION || context.exactCommitment || witness.length == 0) {
            revert AVACoreTypes.InvalidState(context.requestId);
        }
        record = _request(AVARequestAllocation(REQUEST_ALLOCATION).decisionRequestIdByExecution(context.requestId));
        if (
            AVARequestAllocation(REQUEST_ALLOCATION).getRequest(context.requestId).creator != record.creator
                || context.appId != record.input.appId || context.workflowKey != record.input.workflowKey
                || context.packageId != record.input.packageId || context.executor != record.input.executor
                || context.responseClass != record.input.responseClass || context.burdenHash != record.input.burdenHash
                || context.validUntil != record.input.validUntil || block.timestamp >= context.validUntil
        ) revert AVACoreTypes.InvalidState(context.requestId);
    }

    function _request(uint256 id) private view returns (AtomicRequest storage record) {
        record = requests[id];
        if (record.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _requestHashKey(bytes32 appId, bytes32 workflowKey, bytes32 requestHash) private pure returns (bytes32) {
        return keccak256(abi.encode(appId, workflowKey, requestHash));
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(address(GOVERNANCE_KERNEL), REQUEST_ALLOCATION));
    }
}
