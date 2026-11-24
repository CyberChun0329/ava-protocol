// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACapabilityKeys} from "../../core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVAWorkflowPolicyRouter} from "../../core/AVAWorkflowPolicyRouter.sol";
import {IAVAApplicationModule} from "../../interfaces/IAVAApplicationModule.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVAAuthorityMatrix} from "../../core/AVAAuthorityMatrix.sol";
import {AVAIdentityRegistry} from "../../core/AVAIdentityRegistry.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {IAVAExtensionPolicyModule} from "../shared/IAVAExtensionPolicyModule.sol";
import {IAVADecisionExecutionPolicy} from "../decisions/IAVADecisionRegistry.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {AVAExecutionApproval, IAVAExecutionApprovalPolicy} from "./IAVAExecutionApprovalPolicy.sol";
import {IAVACorrectionReview} from "../../core/interfaces/IAVACorrectionReview.sol";

interface IAVARequestCorrectionTarget {
    struct Target {
        uint256 requestId;
        uint256 packageId;
        uint256 head;
        uint256 withdrawalId;
        uint256 filingEvidenceId;
        bytes32 challengerSubjectId;
        address allocator;
        address filedBy;
        uint8 kind;
        uint8 outcome;
        bool consumed;
        bool completed;
        bytes32 effectHash;
    }
}
import {IAVAAllocationPolicyModule, IAVAAntiAbusePolicyModule} from "../../core/interfaces/IAVACoreRuleModules.sol";

/// @notice Immutable witness custody and live eligibility checks for one request extension.
/// @dev Domain matching and joint sufficiency remain with the request's verified policy.
contract AVARequestSupport {
    address public immutable REQUEST_ALLOCATION;
    address private immutable EXECUTION_HELPER;
    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    AVAAuthorityMatrix private immutable AUTHORITY_MATRIX;
    AVAIdentityRegistry private immutable IDENTITY_REGISTRY;
    AVACoreRulePackageRegistry private immutable RULE_PACKAGE_REGISTRY;
    AVAEvidenceRegistry private immutable EVIDENCE_REGISTRY;
    AVAWorkflowPolicyRouter private immutable POLICY_ROUTER;
    mapping(uint256 => IAVARequestPolicy.RequestContext) private contexts;
    mapping(uint256 => IAVARequestPolicy.WitnessInput[]) private witnesses;
    mapping(uint256 => uint256) private exactTransitions;

    struct HostComponents {
        AVAAuthorityMatrix authority;
        AVAIdentityRegistry identity;
        AVACoreRulePackageRegistry packages;
        AVAEvidenceRegistry evidence;
        AVAWorkflowPolicyRouter router;
    }

    constructor(AVAGovernanceKernel kernel, address executionHelper, HostComponents memory host) {
        REQUEST_ALLOCATION = msg.sender;
        GOVERNANCE_KERNEL = kernel;
        EXECUTION_HELPER = executionHelper;
        AUTHORITY_MATRIX = host.authority;
        IDENTITY_REGISTRY = host.identity;
        RULE_PACKAGE_REGISTRY = host.packages;
        EVIDENCE_REGISTRY = host.evidence;
        POLICY_ROUTER = host.router;
    }

    struct ResolutionTerms {
        uint256 challengeId;
        uint256 expectedHead;
        uint256 evidenceId;
        uint8 outcome;
        bytes32 reasonHash;
        address asset;
        address recipient;
        uint256 amount;
        address actor;
        bytes32 roleKey;
        bytes32 authorityId;
        bytes32 decisionHash;
        bytes32 contextHash;
    }

    function _activeCorrectionEvidence(uint256 id, uint256 evidenceId) private view returns (bytes32) {
        IAVARequestPolicy.RequestContext memory context = _context(id);
        return
            EVIDENCE_REGISTRY.requireCorrectionSupport(
                evidenceId, context.packageId, context.appId, context.workflowKey
            );
    }

    function validateResolutionTerms(ResolutionTerms calldata input, IAVARequestCorrectionTarget.Target calldata target)
        external
        view
    {
        if (msg.sender != REQUEST_ALLOCATION) revert AVACoreTypes.InvalidState(input.challengeId);
        if (
            target.outcome != 0 || input.reasonHash == bytes32(0) || input.expectedHead != target.head
                || input.actor == target.filedBy || input.actor == target.allocator
        ) {
            revert AVACoreTypes.InvalidState(input.challengeId);
        }
        if (input.outcome == 5) {
            if (
                input.evidenceId != 0
                    || (IDENTITY_REGISTRY.getSubjectContext(target.challengerSubjectId).active
                        && EVIDENCE_REGISTRY.isEvidenceAvailableForPackage(target.filingEvidenceId, target.packageId))
            ) {
                revert AVACoreTypes.InvalidState(input.challengeId);
            }
        } else if (input.outcome != 6 || input.evidenceId != 0) {
            _activeCorrectionEvidence(target.requestId, input.evidenceId);
        }
        _validateRemedy(target, input.outcome, input.asset, input.recipient, input.amount, input.challengeId);
        if (input.outcome == 2) {
            if (target.kind != 0 || target.consumed || target.withdrawalId != 0) {
                revert AVACoreTypes.InvalidState(input.challengeId);
            }
        } else if (input.outcome == 3) {
            if (!target.consumed) revert AVACoreTypes.InvalidState(input.challengeId);
        } else if (input.outcome == 6) {
            if (target.withdrawalId == 0) revert AVACoreTypes.InvalidState(input.challengeId);
        } else if (input.outcome != 5 && input.outcome != 1 && input.outcome != 4) {
            revert AVACoreTypes.InvalidState(input.challengeId);
        }
        bytes32 resolveAction = keccak256("ava.extension.request.challenge.resolve.v1");
        CorrectionInput memory correction = CorrectionInput({
            actionKey: resolveAction,
            roleKey: input.roleKey,
            authorityId: input.authorityId,
            evidenceId: input.evidenceId,
            decisionHash: input.decisionHash,
            challengeId: input.challengeId,
            outcomeKey: bytes32(uint256(input.outcome)),
            validateDisclosure: false,
            actor: input.actor
        });
        _validateCorrection(target.requestId, correction);
        CorrectionExtensionInput memory extension = CorrectionExtensionInput({
            capability: AVACapabilityKeys.RESTORATION,
            actionKey: resolveAction,
            scopeKey: bytes32(uint256(target.kind)),
            evidenceId: input.evidenceId,
            challengeId: input.challengeId,
            remedyAmount: input.amount,
            payloadHash: input.decisionHash,
            contextHash: input.contextHash,
            authorityId: input.authorityId,
            actor: input.actor
        });
        _validateCorrectionExtension(target.requestId, extension);
        if (input.outcome == 4) {
            bytes32 remedyAction = keccak256("ava.extension.request.remedy.authorise.v1");
            // RemedyTerms is a static three-word tuple, preserving the original commitment ABI.
            bytes32 remedyHash =
                keccak256(abi.encode(remedyAction, input.decisionHash, input.asset, input.recipient, input.amount));
            correction.actionKey = remedyAction;
            correction.decisionHash = remedyHash;
            _validateCorrection(target.requestId, correction);
            extension.capability = AVACapabilityKeys.VALUE_EXECUTION;
            extension.actionKey = remedyAction;
            extension.payloadHash = remedyHash;
            _validateCorrectionExtension(target.requestId, extension);
        }
    }

    function validateCoreReviewTerms(
        IAVACorrectionReview.ReviewTerms calldata review,
        IAVARequestCorrectionTarget.Target calldata target
    ) external view returns (uint8 outcome) {
        if (msg.sender != REQUEST_ALLOCATION || target.outcome != 0 || review.expectedTargetVersion != target.head) {
            revert AVACoreTypes.InvalidState(review.originCaseId);
        }
        // Numeric outcomes preserve the request extension's additive enum ABI.
        if (review.outcome == IAVACorrectionReview.Outcome.Affirmed) {
            outcome = 1;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Withdrawn) {
            if (target.kind != 0 || target.consumed || target.withdrawalId != 0) {
                revert AVACoreTypes.InvalidState(review.originCaseId);
            }
            outcome = 2;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Residual) {
            outcome = 7;
        } else if (review.outcome == IAVACorrectionReview.Outcome.Compensate) {
            outcome = 4;
        } else if (review.outcome == IAVACorrectionReview.Outcome.EvidenceUnavailable) {
            outcome = 5;
        } else if (review.outcome == IAVACorrectionReview.Outcome.TargetChanged) {
            outcome = target.withdrawalId != 0 ? 6 : 7;
        } else {
            revert AVACoreTypes.InvalidState(review.originCaseId);
        }
        _validateRemedy(target, outcome, review.asset, review.recipient, review.amount, review.originCaseId);
    }

    function _validateRemedy(
        IAVARequestCorrectionTarget.Target memory target,
        uint8 outcome,
        address asset,
        address recipient,
        uint256 amount,
        uint256 id
    ) private view {
        if (outcome == 4) {
            if (
                !target.completed || !target.consumed || target.effectHash == bytes32(0) || asset.code.length == 0
                    || recipient == address(0) || recipient == REQUEST_ALLOCATION || amount == 0
            ) revert AVACoreTypes.InvalidState(id);
        } else if (asset != address(0) || recipient != address(0) || amount != 0) {
            revert AVACoreTypes.InvalidState(id);
        }
    }

    function bind(
        IAVARequestPolicy.RequestContext calldata context,
        uint256 primaryTransitionId,
        IAVARequestPolicy.WitnessInput[] calldata input
    ) external returns (bytes32) {
        if (
            msg.sender != REQUEST_ALLOCATION || context.requestAllocation != REQUEST_ALLOCATION
                || context.requestId == 0 || contexts[context.requestId].requestId != 0
        ) revert AVACoreTypes.InvalidState(context.requestId);
        contexts[context.requestId] = context;
        if (context.exactCommitment) {
            if (input.length != 0) revert AVACoreTypes.InvalidState(context.requestId);
            exactTransitions[context.requestId] = primaryTransitionId;
            IAVARequestPolicy.WitnessInput[] memory exact = new IAVARequestPolicy.WitnessInput[](1);
            exact[0] = _exactWitness(context, primaryTransitionId);
            return
                keccak256(abi.encode(block.chainid, REQUEST_ALLOCATION, context.requestId, context.commitment, exact));
        } else {
            if (input.length == 0 || input.length > 16) revert AVACoreTypes.EmptyValue();
            for (uint256 i; i < input.length; ++i) {
                witnesses[context.requestId].push(input[i]);
            }
        }
        return keccak256(
            abi.encode(
                block.chainid, REQUEST_ALLOCATION, context.requestId, context.commitment, witnesses[context.requestId]
            )
        );
    }

    function getWitness(uint256 id) external view returns (IAVARequestPolicy.WitnessInput[] memory) {
        IAVARequestPolicy.RequestContext memory context = _context(id);
        if (context.exactCommitment) {
            IAVARequestPolicy.WitnessInput[] memory exact = new IAVARequestPolicy.WitnessInput[](1);
            exact[0] = _exactWitness(context, exactTransitions[id]);
            return exact;
        }
        return witnesses[id];
    }

    function _exactWitness(IAVARequestPolicy.RequestContext memory context, uint256 transitionId)
        private
        pure
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        return IAVARequestPolicy.WitnessInput(
            context.primaryRecognisedStateId,
            transitionId,
            IAVARequestPolicy.RecognitionScope(context.commitment, context.responseClass, context.burdenHash)
        );
    }

    function requestContext(uint256 id) external view returns (IAVARequestPolicy.RequestContext memory) {
        return _context(id);
    }

    function occurrenceChanged(uint256 id) external view returns (bool) {
        IAVARequestPolicy.RequestContext storage context = contexts[id];
        if (context.requestId == 0) revert AVACoreTypes.UnknownReference(id);
        if (context.exactCommitment) {
            AVAGovernanceKernel.RecognisedStateReference memory source =
                GOVERNANCE_KERNEL.getRecognisedStateReference(context.primaryRecognisedStateId);
            return source.lastTransitionId != exactTransitions[id]
                || GOVERNANCE_KERNEL.DEPENDENCIES().dependenciesChanged(source.governedObjectId);
        }
        IAVARequestPolicy.WitnessInput[] storage input = witnesses[id];
        for (uint256 i; i < input.length; ++i) {
            AVAGovernanceKernel.RecognisedStateReference memory source =
                GOVERNANCE_KERNEL.getRecognisedStateReference(input[i].recognisedStateId);
            if (
                source.lastTransitionId != input[i].transitionId
                    || GOVERNANCE_KERNEL.DEPENDENCIES().dependenciesChanged(source.governedObjectId)
            ) return true;
        }
        return false;
    }

    function resolve(uint256 id)
        public
        view
        returns (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory resolved)
    {
        context = _context(id);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory receiving =
            RULE_PACKAGE_REGISTRY.getVerifiedPackageContext(context.packageId);
        (resolved,) = _resolveWitnesses(id, context, receiving);
    }

    function _resolveWitnesses(
        uint256 id,
        IAVARequestPolicy.RequestContext memory context,
        AVACoreRulePackageRegistry.VerifiedPackageContext memory receiving
    ) private view returns (IAVARequestPolicy.Witness[] memory resolved, uint256 primaryIndex) {
        if (receiving.appId != context.appId || receiving.workflowKey != context.workflowKey) {
            revert AVACoreTypes.InvalidState(context.packageId);
        }
        IAVARequestPolicy.WitnessInput[] storage input = witnesses[id];
        uint256 length = context.exactCommitment ? 1 : input.length;
        resolved = new IAVARequestPolicy.Witness[](length);
        uint256 previousId;
        bool primaryFound;
        for (uint256 i; i < length; ++i) {
            IAVARequestPolicy.WitnessInput memory item =
                context.exactCommitment ? _exactWitness(context, exactTransitions[id]) : input[i];
            if (item.recognisedStateId <= previousId) revert AVACoreTypes.InvalidState(item.recognisedStateId);
            previousId = item.recognisedStateId;
            AVAGovernanceKernel.RecognisedStateReference memory state =
                GOVERNANCE_KERNEL.getRecognisedStateReference(item.recognisedStateId);
            if (
                state.appId != context.appId || state.workflowKey != context.workflowKey
                    || state.stage != AVACoreTypes.Stage.Verification
                    || (state.status != AVACoreTypes.RecognisedStateStatus.Vested
                        && state.status != AVACoreTypes.RecognisedStateStatus.Restored)
                    || state.lastTransitionId != item.transitionId
            ) revert AVACoreTypes.InvalidState(state.id);
            IDENTITY_REGISTRY.requireActiveSubjectReference(state.subjectId, context.appId);
            // The receiving package was fully verified above in this view call.
            // Each distinct historical source package is verified in this view call.
            if (state.packageId != context.packageId) {
                bool verified;
                for (uint256 j; j < i; ++j) {
                    if (resolved[j].packageId == state.packageId) {
                        verified = true;
                        break;
                    }
                }
                if (!verified) {
                    AVACoreRulePackageRegistry.VerifiedPackageContext memory sourceRules =
                        RULE_PACKAGE_REGISTRY.getVerifiedPackageContext(state.packageId);
                    if (sourceRules.appId != state.appId || sourceRules.workflowKey != state.workflowKey) {
                        revert AVACoreTypes.InvalidState(state.packageId);
                    }
                }
            }
            GOVERNANCE_KERNEL.DEPENDENCIES().requireCurrent(state.governedObjectId);
            (
                AVAGovernanceKernel.GovernedObjectReference memory objectRecord,
                bytes32 objectCommitment,
                bytes32 metadataHash
            ) = GOVERNANCE_KERNEL.getGovernedObjectCommitmentReference(state.governedObjectId);
            if (
                objectRecord.appId != state.appId || objectRecord.workflowKey != state.workflowKey
                    || objectRecord.packageId != state.packageId || objectRecord.subjectId != state.subjectId
                    || objectRecord.evidenceReceiptId != state.evidenceReceiptId
                    || objectRecord.disclosurePolicyId != state.disclosurePolicyId
            ) revert AVACoreTypes.InvalidState(state.governedObjectId);
            _requireEvidence(state);
            if (context.exactCommitment) {
                if (length != 1 || objectCommitment != context.commitment) {
                    revert AVACoreTypes.InvalidState(state.id);
                }
            } else if (
                item.scope.claimHash == bytes32(0) || item.scope.useHash == bytes32(0)
                    || item.scope.burdenHash == bytes32(0)
                    || metadataHash != keccak256(abi.encode(keccak256("ava.recognition-scope.v1"), item.scope))
            ) {
                revert AVACoreTypes.InvalidState(state.id);
            }
            if (state.id == context.primaryRecognisedStateId) {
                if (context.exactCommitment && state.packageId != context.packageId) {
                    revert AVACoreTypes.InvalidState(state.id);
                }
                primaryFound = true;
                primaryIndex = i;
            }
            resolved[i] = IAVARequestPolicy.Witness(
                state.id,
                item.transitionId,
                state.governedObjectId,
                state.packageId,
                objectRecord.objectTypeKey,
                state.subjectId,
                state.evidenceReceiptId,
                item.scope
            );
        }
        if (!primaryFound) revert AVACoreTypes.InvalidState(id);
    }

    struct CorrectionInput {
        bytes32 actionKey;
        bytes32 roleKey;
        bytes32 authorityId;
        uint256 evidenceId;
        bytes32 decisionHash;
        uint256 challengeId;
        bytes32 outcomeKey;
        bool validateDisclosure;
        address actor;
    }

    function validateSupport(uint256 id) external view {
        IAVARequestPolicy.RequestContext memory context = _context(id);
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.ALLOCATION;
        (AVACoreRulePackageRegistry.VerifiedPackageContext memory receiving, address[] memory modules) =
            RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(context.packageId, keys);
        (IAVARequestPolicy.Witness[] memory resolved,) = _resolveWitnesses(id, context, receiving);
        // Preserve witness failures before the original missing-policy error.
        if (modules[0] == address(0)) revert AVACoreTypes.UnknownReference(context.packageId);
        IAVARequestPolicy(modules[0]).validateResponseSupport(context, resolved);
    }

    function requireDecisionBridge(uint256 id, address caller) external view {
        _requireOwner(id);
        if (IAVADecisionExecutionPolicy(address(_policy(_context(id).packageId))).DECISION_REGISTRY() != caller) {
            revert AVACoreTypes.NotAuthorised(caller, AVACoreTypes.ACTION_RECORD_ALLOCATION);
        }
    }

    function validateDecision(uint256 id, IAVARequestPolicy.DecisionContext calldata decision) external view {
        _validateDecision(id, decision, false);
    }

    /// @notice Only execution may rely on a package's retained approval policy.
    function validateExecution(uint256 id, IAVARequestPolicy.DecisionContext calldata decision) external view {
        _validateDecision(id, decision, true);
    }

    function _validateDecision(uint256 id, IAVARequestPolicy.DecisionContext calldata decision, bool execution)
        private
        view
    {
        _requireOwner(id);
        IAVARequestPolicy.RequestContext memory context = _context(id);
        bytes32[] memory keys = new bytes32[](execution ? 4 : 3);
        keys[0] = AVACapabilityKeys.APPLICATION;
        keys[1] = AVACapabilityKeys.ANTI_ABUSE;
        keys[2] = AVACapabilityKeys.ALLOCATION;
        if (execution) keys[3] = AVAExecutionApproval.CAPABILITY;
        (AVACoreRulePackageRegistry.VerifiedPackageContext memory receiving, address[] memory modules) =
            RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(context.packageId, keys);
        (IAVARequestPolicy.Witness[] memory resolved, uint256 primaryIndex) = _resolveWitnesses(id, context, receiving);
        // Keep the original missing-policy error after witness resolution.
        if (modules[2] == address(0)) revert AVACoreTypes.UnknownReference(context.packageId);
        IAVARequestPolicy policy = IAVARequestPolicy(modules[2]);
        // The same resolved support supplies both read-only checks, in their original order.
        policy.validateResponseSupport(context, resolved);
        bool requireCurrentAllocator = true;
        if (execution && modules[3] != address(0)) {
            IAVAExecutionApprovalPolicy(modules[3]).validateExecutionApproval(context, decision);
            requireCurrentAllocator = false;
        }
        _validateAllocation(context, resolved[primaryIndex], decision, modules, requireCurrentAllocator);
        policy.validateRequestAllocation(context, resolved, decision);
    }

    /// @dev Source identities remain historical; ordinary response policies belong to the receiving package.
    function _validateAllocation(
        IAVARequestPolicy.RequestContext memory context,
        IAVARequestPolicy.Witness memory source,
        IAVARequestPolicy.DecisionContext calldata decision,
        address[] memory modules,
        bool requireCurrentAllocator
    ) private view {
        if (
            decision.roleKey == bytes32(0) || decision.authorityId == bytes32(0) || decision.actor == address(0)
                || decision.evaluatedAt != block.timestamp || context.responseClass == bytes32(0)
        ) revert AVACoreTypes.EmptyValue();
        // The primary's current subject, object and evidence were checked during this view's resolution.
        if (requireCurrentAllocator) {
            AUTHORITY_MATRIX.requireAuthorisedSubject(
                decision.actor,
                context.appId,
                decision.roleKey,
                AVACoreTypes.ACTION_RECORD_ALLOCATION,
                decision.authorityId
            );
        }
        IAVAApplicationModule.DownstreamRecordContext memory record = IAVAApplicationModule.DownstreamRecordContext({
            appId: context.appId,
            workflowKey: context.workflowKey,
            packageId: context.packageId,
            actionKey: AVACoreTypes.ACTION_RECORD_ALLOCATION,
            roleKey: decision.roleKey,
            recognisedStateId: source.recognisedStateId,
            governedObjectId: source.governedObjectId,
            objectTypeKey: source.objectTypeKey,
            subjectId: source.subjectId,
            evidenceReceiptId: source.evidenceReceiptId,
            recordTypeKey: context.responseClass,
            authorityId: decision.authorityId,
            actor: decision.actor
        });
        IAVAApplicationModule(modules[0]).validateDownstreamRecord(record);
        if (modules[1] != address(0)) {
            IAVAAntiAbusePolicyModule(modules[1])
                .validateAntiAbuse(
                    IAVAAntiAbusePolicyModule.AntiAbuseContext({
                        appId: context.appId,
                        workflowKey: context.workflowKey,
                        packageId: context.packageId,
                        actionKey: AVACoreTypes.ACTION_RECORD_ALLOCATION,
                        roleKey: decision.roleKey,
                        targetId: source.recognisedStateId,
                        targetTypeKey: context.responseClass,
                        actorSubjectId: decision.authorityId,
                        targetSubjectId: source.subjectId,
                        authorityId: decision.authorityId,
                        actor: decision.actor
                    })
                );
        }
        IAVAAllocationPolicyModule(modules[2])
            .validateAllocation(IAVAAllocationPolicyModule.AllocationPolicyContext({record: record, units: 1}));
    }

    function _requireEvidence(AVAGovernanceKernel.RecognisedStateReference memory source) private view {
        (bytes32 appId, bytes32 workflowKey, uint256 packageId, bytes32 subjectId, uint256 disclosureId) =
            EVIDENCE_REGISTRY.requireUsableEvidenceReferenceForPackage(source.evidenceReceiptId, source.packageId);
        if (
            appId != source.appId || workflowKey != source.workflowKey || packageId != source.packageId
                || subjectId != source.subjectId || disclosureId != source.disclosurePolicyId
        ) revert AVACoreTypes.InvalidState(source.evidenceReceiptId);
    }

    /// @dev Historical correction deliberately does not require live support or an unexpired request.
    function validateCorrection(uint256 id, CorrectionInput calldata input) external view {
        _requireOwner(id);
        _validateCorrection(id, input);
    }

    function validateRecovery(uint256 id, CorrectionInput calldata input) external view {
        if (
            msg.sender != EXECUTION_HELPER
                || input.actionKey != keccak256("ava.extension.request.recovery.authorise.v1")
        ) {
            revert AVACoreTypes.InvalidState(id);
        }
        bytes32 subject = _activeCorrectionEvidence(id, input.evidenceId);
        if (subject != input.authorityId) revert AVACoreTypes.SubjectMismatch(input.authorityId, subject);
        _validateCorrection(id, input);
        IAVARequestPolicy.RequestContext memory context = _context(id);
        _validateCorrectionExtension(
            id,
            CorrectionExtensionInput({
                capability: AVACapabilityKeys.RESTORATION,
                actionKey: input.actionKey,
                scopeKey: bytes32(input.challengeId),
                evidenceId: input.evidenceId,
                challengeId: input.challengeId,
                remedyAmount: 0,
                payloadHash: input.decisionHash,
                contextHash: context.commitment,
                authorityId: input.authorityId,
                actor: input.actor
            })
        );
    }

    function _validateCorrection(uint256 id, CorrectionInput memory input) private view {
        IAVARequestPolicy.RequestContext memory context = _context(id);
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(context.primaryRecognisedStateId);
        AUTHORITY_MATRIX.requireAuthorisedSubject(
            input.actor, context.appId, input.roleKey, input.actionKey, input.authorityId
        );
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.APPLICATION;
        (AVACoreRulePackageRegistry.VerifiedPackageContext memory packageContext, address[] memory modules) =
            RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(context.packageId, keys);
        if (packageContext.appId != context.appId || packageContext.workflowKey != context.workflowKey) {
            revert AVACoreTypes.InvalidState(context.packageId);
        }
        AVAGovernanceKernel.GovernedObjectReference memory objectRecord =
            GOVERNANCE_KERNEL.getGovernedObjectReference(source.governedObjectId);
        IAVAApplicationModule(modules[0])
            .validateDownstreamRecord(
                IAVAApplicationModule.DownstreamRecordContext({
                    appId: context.appId,
                    workflowKey: context.workflowKey,
                    packageId: context.packageId,
                    actionKey: input.actionKey,
                    roleKey: input.roleKey,
                    recognisedStateId: context.primaryRecognisedStateId,
                    governedObjectId: source.governedObjectId,
                    objectTypeKey: objectRecord.objectTypeKey,
                    subjectId: source.subjectId,
                    evidenceReceiptId: input.evidenceId,
                    recordTypeKey: context.responseClass,
                    authorityId: input.authorityId,
                    actor: input.actor
                })
            );
        uint256 disclosureId =
            input.evidenceId == 0 ? 0 : EVIDENCE_REGISTRY.getEvidenceReference(input.evidenceId).disclosurePolicyId;
        POLICY_ROUTER.validateChallengePolicies(
            AVAWorkflowPolicyRouter.ChallengePolicyInput({
                appId: context.appId,
                workflowKey: context.workflowKey,
                packageId: context.packageId,
                actionKey: input.actionKey,
                roleKey: input.roleKey,
                stage: AVACoreTypes.Stage.Verification,
                objectTypeKey: objectRecord.objectTypeKey,
                challengeId: input.challengeId,
                recognisedStateId: context.primaryRecognisedStateId,
                actorSubjectId: input.authorityId,
                targetSubjectId: source.subjectId,
                outcomeKey: input.outcomeKey,
                targetStatus: source.status,
                evidenceId: input.evidenceId,
                disclosurePolicyId: disclosureId,
                authorityId: input.authorityId,
                decisionHash: input.decisionHash,
                actor: input.actor,
                validateDisclosure: input.validateDisclosure,
                validateAuthority: true
            })
        );
    }

    struct CorrectionExtensionInput {
        bytes32 capability;
        bytes32 actionKey;
        bytes32 scopeKey;
        uint256 evidenceId;
        uint256 challengeId;
        uint256 remedyAmount;
        bytes32 payloadHash;
        bytes32 contextHash;
        bytes32 authorityId;
        address actor;
    }

    function _validateCorrectionExtension(uint256 id, CorrectionExtensionInput memory input) private view {
        IAVARequestPolicy.RequestContext memory context = _context(id);
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(context.primaryRecognisedStateId);
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = input.capability;
        (, address[] memory modules) = RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(context.packageId, keys);
        if (modules[0] == address(0)) revert AVACoreTypes.UnknownReference(context.packageId);
        uint256 disclosureId =
            input.evidenceId == 0 ? 0 : EVIDENCE_REGISTRY.getEvidenceReference(input.evidenceId).disclosurePolicyId;
        uint256 primaryTransition;
        if (context.exactCommitment) {
            primaryTransition = exactTransitions[id];
        } else {
            IAVARequestPolicy.WitnessInput[] storage witness = witnesses[id];
            for (uint256 i; i < witness.length; ++i) {
                if (witness[i].recognisedStateId == context.primaryRecognisedStateId) {
                    primaryTransition = witness[i].transitionId;
                    break;
                }
            }
        }
        IAVAExtensionPolicyModule(modules[0])
            .validateExtensionRecord(
                IAVAExtensionPolicyModule.ExtensionPolicyContext({
                    appId: context.appId,
                    workflowKey: context.workflowKey,
                    packageId: context.packageId,
                    capabilityKey: input.capability,
                    actionKey: input.actionKey,
                    recordTypeKey: context.responseClass,
                    scopeKey: input.scopeKey,
                    sourceTypeKey: keccak256("ava.request-allocation.commitment.v1"),
                    recognisedStateId: context.primaryRecognisedStateId,
                    recognisedStateTransitionId: primaryTransition,
                    subjectId: source.subjectId,
                    evidenceId: input.evidenceId,
                    disclosurePolicyId: disclosureId,
                    sourceRecordId: input.challengeId,
                    unsignedValue: input.remedyAmount,
                    validUntil: context.validUntil,
                    payloadHash: input.payloadHash,
                    contextHash: input.contextHash,
                    authorityId: input.authorityId,
                    actor: input.actor
                })
            );
    }

    function _requireOwner(uint256 id) private view {
        if (msg.sender != REQUEST_ALLOCATION) revert AVACoreTypes.InvalidState(id);
    }

    function _policy(uint256 packageId) private view returns (IAVARequestPolicy) {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = AVACapabilityKeys.ALLOCATION;
        (, address[] memory modules) = RULE_PACKAGE_REGISTRY.getVerifiedModulesCompact(packageId, keys);
        if (modules[0] == address(0)) revert AVACoreTypes.UnknownReference(packageId);
        return IAVARequestPolicy(modules[0]);
    }

    function _context(uint256 id) private view returns (IAVARequestPolicy.RequestContext memory context) {
        context = contexts[id];
        if (context.requestId == 0) revert AVACoreTypes.UnknownReference(id);
    }
}
