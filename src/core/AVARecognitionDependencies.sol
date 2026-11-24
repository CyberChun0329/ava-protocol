// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "./AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "./AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "./AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "./AVAGovernanceKernel.sol";

/// @notice Immutable, occurrence-pinned provenance for dependent governed objects.
/// @dev Eligibility loss never mutates descendants or substitutes a later source occurrence.
contract AVARecognitionDependencies {
    struct SourceQualification {
        uint256 recognisedStateId;
        uint256 transitionId;
        uint256 objectId;
        bool eligible;
    }

    struct SourcePackageCache {
        bool populated;
        AVACoreRulePackageRegistry.VerifiedPackageContext context;
    }

    uint256 public constant MAX_DEPENDENCIES = 16;
    uint256 public constant MAX_TRAVERSAL = 64;
    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    mapping(uint256 => AVACoreTypes.SourceOccurrence[]) private dependencies;

    // Kernel creates this helper in its own constructor; do not call it until deployment completes.
    constructor(AVAGovernanceKernel kernel) {
        GOVERNANCE_KERNEL = kernel;
    }

    function bind(uint256 objectId, AVACoreTypes.SourceOccurrence[] calldata input) external {
        if (msg.sender != address(GOVERNANCE_KERNEL)) {
            revert AVACoreTypes.NotAuthorised(msg.sender, AVACoreTypes.ACTION_REGISTER_GOVERNED_OBJECT);
        }
        if (dependencies[objectId].length != 0 || input.length == 0 || input.length > MAX_DEPENDENCIES) {
            revert AVACoreTypes.InvalidState(objectId);
        }
        GOVERNANCE_KERNEL.getGovernedObjectReference(objectId);
        uint256 previous;
        for (uint256 i; i < input.length; ++i) {
            if (input[i].recognisedStateId <= previous || input[i].transitionId == 0) {
                revert AVACoreTypes.InvalidState(input[i].recognisedStateId);
            }
            previous = input[i].recognisedStateId;
            dependencies[objectId].push(input[i]);
        }
        requireCurrent(objectId);
    }

    function getDependencies(uint256 objectId) external view returns (AVACoreTypes.SourceOccurrence[] memory) {
        GOVERNANCE_KERNEL.getGovernedObjectReference(objectId);
        return dependencies[objectId];
    }

    function requireCurrent(uint256 objectId) public view {
        if (!dependenciesCurrent(objectId)) revert AVACoreTypes.InvalidState(objectId);
    }

    function dependenciesChanged(uint256 objectId) external view returns (bool) {
        return !dependenciesCurrent(objectId);
    }

    function dependenciesCurrent(uint256 objectId) public view returns (bool current) {
        AVAGovernanceKernel.GovernedObjectReference memory root = GOVERNANCE_KERNEL.getGovernedObjectReference(objectId);
        uint256 firstParent = objectId;
        uint256 traversed;
        current = true;
        if (dependencies[firstParent].length == 0) return current;
        // This cache lives only for this traversal; each new package is verified before reuse.
        SourcePackageCache memory sourcePackage;
        // A single-parent prefix cannot revisit its descendants: every edge must
        // point to an older object. Empty, singleton and chain calls need no memo.
        while (dependencies[firstParent].length == 1) {
            if (++traversed > MAX_TRAVERSAL) revert AVACoreTypes.InvalidState(objectId);
            (uint256 ancestor, bool eligible) =
                _sourceCurrent(dependencies[firstParent][0], root.appId, firstParent, sourcePackage);
            firstParent = ancestor;
            if (!eligible) current = false;
        }
        if (dependencies[firstParent].length == 0) return current;

        uint256[] memory pending = new uint256[](MAX_TRAVERSAL + 1);
        uint256[] memory expanded = new uint256[](MAX_TRAVERSAL + 1);
        SourceQualification[] memory qualified = new SourceQualification[](MAX_TRAVERSAL);
        uint256 qualifiedCount;
        pending[0] = firstParent;
        uint256 pendingCount = 1;
        uint256 expandedCount;
        while (pendingCount != 0) {
            uint256 parent = pending[--pendingCount];
            bool seen;
            for (uint256 i; i < expandedCount; ++i) {
                if (expanded[i] == parent) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;
            if (expandedCount > MAX_TRAVERSAL) revert AVACoreTypes.InvalidState(objectId);
            expanded[expandedCount++] = parent;
            AVACoreTypes.SourceOccurrence[] storage sources = dependencies[parent];
            for (uint256 i; i < sources.length; ++i) {
                if (++traversed > MAX_TRAVERSAL) revert AVACoreTypes.InvalidState(objectId);
                AVACoreTypes.SourceOccurrence memory pinned = sources[i];
                uint256 known;
                for (; known < qualifiedCount; ++known) {
                    if (
                        qualified[known].recognisedStateId == pinned.recognisedStateId
                            && qualified[known].transitionId == pinned.transitionId
                    ) break;
                }
                uint256 ancestor;
                bool eligible;
                if (known == qualifiedCount) {
                    (ancestor, eligible) = _sourceCurrent(pinned, root.appId, parent, sourcePackage);
                    qualified[qualifiedCount++] =
                        SourceQualification(pinned.recognisedStateId, pinned.transitionId, ancestor, eligible);
                } else {
                    SourceQualification memory prior = qualified[known];
                    ancestor = prior.objectId;
                    eligible = prior.eligible;
                    // Qualification is reusable, but the ordering constraint belongs to each edge.
                    if (ancestor >= parent) revert AVACoreTypes.InvalidState(pinned.recognisedStateId);
                }
                // Continue checking all branches: a known exclusion must not hide technical failures.
                if (!eligible) current = false;
                if (pendingCount > MAX_TRAVERSAL) revert AVACoreTypes.InvalidState(objectId);
                pending[pendingCount++] = ancestor;
            }
        }
    }

    function _sourceCurrent(
        AVACoreTypes.SourceOccurrence memory pinned,
        bytes32 appId,
        uint256 childObjectId,
        SourcePackageCache memory sourcePackage
    ) private view returns (uint256 objectId, bool current) {
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(pinned.recognisedStateId);
        AVAGovernanceKernel.RecognisedStateTransitionReference memory transition =
            GOVERNANCE_KERNEL.getRecognisedStateTransitionReference(pinned.transitionId);
        if (!sourcePackage.populated || sourcePackage.context.packageId != source.packageId) {
            sourcePackage.context =
                GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(source.packageId);
            sourcePackage.populated = true;
        }
        AVACoreRulePackageRegistry.VerifiedPackageContext memory rules = sourcePackage.context;
        AVACoreRulePackageRegistry.VerifiedPackageContext memory decisionRules = transition.decisionPackageId
            == source.packageId
            ? rules
            : GOVERNANCE_KERNEL.RULE_PACKAGE_REGISTRY().getVerifiedPackageContext(transition.decisionPackageId);
        bytes32 subjectAppId = GOVERNANCE_KERNEL.IDENTITY_REGISTRY().getSubjectContext(source.subjectId).appId;
        AVAEvidenceRegistry.EvidenceReference memory evidence =
            GOVERNANCE_KERNEL.EVIDENCE_REGISTRY().getEvidenceReference(source.evidenceReceiptId);
        if (
            source.appId != appId || source.governedObjectId >= childObjectId
                || transition.recognisedStateId != source.id || transition.governedObjectId != source.governedObjectId
                || transition.appId != source.appId || transition.workflowKey != source.workflowKey
                || transition.packageId != source.packageId || transition.evidenceReceiptId != source.evidenceReceiptId
                || (transition.toStatus != AVACoreTypes.RecognisedStateStatus.Vested
                    && transition.toStatus != AVACoreTypes.RecognisedStateStatus.Restored)
                || rules.appId != source.appId || rules.workflowKey != source.workflowKey
                || decisionRules.appId != source.appId || decisionRules.workflowKey != source.workflowKey
                || subjectAppId != source.appId || evidence.appId != source.appId
                || evidence.workflowKey != source.workflowKey || evidence.packageId != source.packageId
                || evidence.subjectId != source.subjectId || evidence.disclosurePolicyId != source.disclosurePolicyId
        ) revert AVACoreTypes.InvalidState(source.id);
        objectId = source.governedObjectId;
        current = source.stage == AVACoreTypes.Stage.Verification && source.lastTransitionId == pinned.transitionId
            && (source.status == AVACoreTypes.RecognisedStateStatus.Vested
                || source.status == AVACoreTypes.RecognisedStateStatus.Restored);
        if (current) {
            current = GOVERNANCE_KERNEL.EVIDENCE_REGISTRY()
                .isEvidenceAvailableForPackage(source.evidenceReceiptId, source.packageId);
        }
    }
}
