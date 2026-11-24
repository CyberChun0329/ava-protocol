// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

// Shared substrate build surface. Application samples are imported by their tests.
import "../AVAApplicationRegistry.sol";
import "../core/AVAIdentityRegistry.sol";
import "../core/AVAAuthorityMatrix.sol";
import "../core/AVACoreRulePackageRegistry.sol";
import "../core/AVADisclosurePolicyRegistry.sol";
import "../core/AVAEvidenceRegistry.sol";
import "../core/AVAGovernanceKernel.sol";
import "../core/AVAWorkflowPolicyRouter.sol";
import "../extensions/challenge/AVAChallengeExtension.sol";
import "../extensions/downstream/AVADownstreamRecordExtensions.sol";
import "../extensions/requests/AVARequestAllocation.sol";
import "../extensions/requests/AVABoundRequestPolicy.sol";
import "../extensions/privacy/AVAPrivacyRegistry.sol";
import "../extensions/privacy/AVAConfidentialEvidencePolicy.sol";
import "../extensions/privacy/AVABoundConfidentialEvidencePolicy.sol";
import "../extensions/privacy/AVAEvidenceResourceBinding.sol";
import "../extensions/privacy/AVAGovernedDisclosure.sol";

import "../extensions/decisions/AVARecognisedDecisionPolicy.sol";
import "../extensions/decisions/AVAResolvedDecisionPolicy.sol";
import "../extensions/decisions/AVADecisionRegistry.sol";
import "../extensions/decisions/AVAFiniteDecisionPolicy.sol";
import "../extensions/decisions/AVABasicProcedurePolicy.sol";
import "../extensions/decisions/AVAProcedureAdjudication.sol";
import "../extensions/governance/AVARecognisedRuleGovernance.sol";
import "../extensions/governance/AVALocalRuleRevisionPolicy.sol";
