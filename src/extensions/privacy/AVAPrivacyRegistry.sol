// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVAAuthorityMatrix} from "../../core/AVAAuthorityMatrix.sol";
import {AVACoreTypes} from "../../core/AVACoreTypes.sol";

interface IAVAGovernedDisclosure {
    function PRIVACY_REGISTRY() external view returns (address);
    function isGrantCurrent(uint256 requestId) external view returns (bool);
    function grantEffectHash(uint256 requestId) external view returns (bytes32);
}

/// @notice Public, application-scoped disclosure policies and expiring access decisions.
/// @dev This registry does not hide on-chain data or authenticate readers. An off-chain
/// gateway authenticates random case-scoped personas and releases encrypted material.
/// Purpose limits the authorised disclosure scope; it cannot prove a reader's later use.
contract AVAPrivacyRegistry {
    bytes32 public constant MANAGE_POLICY = keccak256("ava.privacy.manage-policy.v1");
    bytes32 public constant MANAGE_CASE = keccak256("ava.privacy.manage-case.v1");
    bytes32 public constant REGISTER_RESOURCE = keccak256("ava.privacy.register-resource.v1");
    bytes32 public constant GRANT_ACCESS = keccak256("ava.privacy.grant-access.v1");
    uint256 public constant MAX_RULES = 64;
    uint256 public constant MAX_GRANTS = 64;

    struct Rule {
        bytes32 materialClass;
        bytes32 readerRole;
        bytes32 purpose;
        uint32 phaseMask;
        uint64 maxLeaseSeconds;
        address allocationExecutor;
    }

    struct Policy {
        bytes32 appId;
        bool active;
        Rule[] rules;
    }

    struct CaseRecord {
        bytes32 appId;
        uint256 policyId;
        uint8 phase;
    }

    struct Resource {
        bytes32 caseId;
        bytes32 materialClass;
        bytes32 ciphertextHash;
        bool active;
    }

    struct Membership {
        uint64 expiresAt;
        uint256 generation;
    }

    struct Grant {
        uint64 expiresAt;
        uint256 membershipGeneration;
        address allocationExecutor;
        uint256 requestId;
    }

    struct GrantInput {
        bytes32 resourceId;
        bytes32 persona;
        bytes32 readerRole;
        bytes32 purpose;
        uint64 expiresAt;
    }

    AVAAuthorityMatrix public immutable AUTHORITY_MATRIX;
    uint256 public nextPolicyId = 1;
    mapping(uint256 => Policy) private policies;
    mapping(uint256 => mapping(bytes32 => Rule)) private policyRules;
    mapping(bytes32 => CaseRecord) private cases;
    mapping(bytes32 => Resource) private resources;
    mapping(bytes32 => Membership) private memberships;
    mapping(bytes32 => Grant) private grants;
    mapping(bytes32 => uint256) private grantRevisions;

    event PolicyPublished(uint256 indexed policyId, bytes32 indexed appId, bytes32 authorityId);
    event PolicyDeactivated(uint256 indexed policyId, bytes32 authorityId);
    event CaseOpened(bytes32 indexed caseId, bytes32 indexed appId, uint256 indexed policyId, bytes32 authorityId);
    event PhaseAdvanced(bytes32 indexed caseId, uint8 phase, bytes32 authorityId);
    event MemberConfigured(
        bytes32 indexed caseId,
        bytes32 indexed persona,
        bytes32 indexed readerRole,
        uint64 expiresAt,
        uint256 generation,
        bytes32 authorityId
    );
    event ResourceRegistered(
        bytes32 indexed resourceId,
        bytes32 indexed caseId,
        bytes32 materialClass,
        bytes32 ciphertextHash,
        bytes32 authorityId
    );
    event ResourceDeactivated(bytes32 indexed resourceId, bytes32 authorityId);
    event AccessConfigured(
        bytes32 indexed resourceId,
        bytes32 indexed persona,
        bytes32 indexed readerRole,
        bytes32 purpose,
        uint64 expiresAt,
        uint256 membershipGeneration,
        bytes32 authorityId
    );

    constructor(AVAAuthorityMatrix authorityMatrix_) {
        if (address(authorityMatrix_).code.length == 0) revert AVACoreTypes.EmptyValue();
        AUTHORITY_MATRIX = authorityMatrix_;
    }

    function publishPolicy(bytes32 appId, bytes32 roleKey, bytes32 authorityId, Rule[] calldata rules)
        external
        returns (uint256 policyId)
    {
        _authorise(appId, roleKey, MANAGE_POLICY, authorityId);
        AUTHORITY_MATRIX.APPLICATION_REGISTRY().requireApplicationReference(appId);
        if (rules.length == 0 || rules.length > MAX_RULES) revert AVACoreTypes.InvalidState(rules.length);
        policyId = nextPolicyId++;
        Policy storage policy = policies[policyId];
        policy.appId = appId;
        policy.active = true;
        for (uint256 i; i < rules.length; ++i) {
            Rule calldata rule = rules[i];
            _readerValues(rule.materialClass, rule.readerRole, rule.purpose);
            if (rule.phaseMask == 0 || rule.maxLeaseSeconds == 0) revert AVACoreTypes.InvalidState(i);
            if (
                rule.allocationExecutor != address(0)
                    && (rule.allocationExecutor.code.length == 0
                        || IAVAGovernedDisclosure(rule.allocationExecutor).PRIVACY_REGISTRY() != address(this))
            ) revert AVACoreTypes.InvalidState(i);
            bytes32 key = _ruleKey(rule.materialClass, rule.readerRole, rule.purpose);
            if (policyRules[policyId][key].phaseMask != 0) revert AVACoreTypes.InvalidState(i);
            policyRules[policyId][key] = rule;
            policy.rules.push(rule);
        }
        emit PolicyPublished(policyId, appId, authorityId);
    }

    function openCase(bytes32 caseId, bytes32 appId, uint256 policyId, bytes32 roleKey, bytes32 authorityId) external {
        if (caseId == bytes32(0)) revert AVACoreTypes.EmptyValue();
        _authorise(appId, roleKey, MANAGE_CASE, authorityId);
        Policy storage policy = _policy(policyId);
        if (!policy.active || cases[caseId].appId != bytes32(0)) revert AVACoreTypes.InvalidState(policyId);
        if (policy.appId != appId) revert AVACoreTypes.CrossApplicationReference(appId, policy.appId);
        cases[caseId] = CaseRecord(appId, policyId, 0);
        emit CaseOpened(caseId, appId, policyId, authorityId);
    }

    /// @notice Advances the disclosure workflow phase, independently of Core recognised-state status.
    function advancePhase(bytes32 caseId, uint8 phase, bytes32 roleKey, bytes32 authorityId) external {
        CaseRecord storage caseRecord = _case(caseId);
        _authorise(caseRecord.appId, roleKey, MANAGE_CASE, authorityId);
        if (phase > 31 || phase <= caseRecord.phase) revert AVACoreTypes.InvalidState(phase);
        caseRecord.phase = phase;
        emit PhaseAdvanced(caseId, phase, authorityId);
    }

    /// @dev Every configuration creates a new generation, including lease renewal.
    /// Disabling requires expiresAt=0. Old grants never survive membership reconfiguration.
    function setMember(
        bytes32 caseId,
        bytes32 persona,
        bytes32 readerRole,
        uint64 expiresAt,
        bool enabled,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        CaseRecord storage caseRecord = _case(caseId);
        _authorise(caseRecord.appId, roleKey, MANAGE_CASE, authorityId);
        if (persona == bytes32(0) || readerRole == bytes32(0)) revert AVACoreTypes.EmptyValue();
        if (enabled) {
            if (!policies[caseRecord.policyId].active || expiresAt <= block.timestamp) {
                revert AVACoreTypes.InvalidState(expiresAt);
            }
        } else if (expiresAt != 0) {
            revert AVACoreTypes.InvalidState(expiresAt);
        }
        Membership storage member = memberships[_memberKey(caseId, persona, readerRole)];
        member.expiresAt = expiresAt;
        ++member.generation;
        emit MemberConfigured(caseId, persona, readerRole, expiresAt, member.generation, authorityId);
    }

    function registerResource(
        bytes32 resourceId,
        bytes32 caseId,
        bytes32 materialClass,
        bytes32 ciphertextHash,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        bool activePolicy = _registrationPolicy(caseId, roleKey, authorityId);
        _registerResource(resourceId, caseId, materialClass, ciphertextHash, authorityId, activePolicy);
    }

    struct ResourceRegistration {
        bytes32 resourceId;
        bytes32 materialClass;
        bytes32 ciphertextHash;
    }

    /// @notice Registers two independent resources under the same case and controller.
    function registerResourcePair(
        bytes32 caseId,
        ResourceRegistration[2] calldata registrations,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        bool activePolicy = _registrationPolicy(caseId, roleKey, authorityId);
        for (uint256 i; i < 2; ++i) {
            ResourceRegistration calldata item = registrations[i];
            _registerResource(item.resourceId, caseId, item.materialClass, item.ciphertextHash, authorityId, activePolicy);
        }
    }

    function _registrationPolicy(bytes32 caseId, bytes32 roleKey, bytes32 authorityId) private view returns (bool) {
        CaseRecord storage caseRecord = _case(caseId);
        _authorise(caseRecord.appId, roleKey, REGISTER_RESOURCE, authorityId);
        return policies[caseRecord.policyId].active;
    }

    function _registerResource(
        bytes32 resourceId,
        bytes32 caseId,
        bytes32 materialClass,
        bytes32 ciphertextHash,
        bytes32 authorityId,
        bool activePolicy
    ) private {
        _readerValues(resourceId, materialClass, ciphertextHash);
        if (resources[resourceId].caseId != bytes32(0) || !activePolicy) {
            revert AVACoreTypes.InvalidState(uint256(resourceId));
        }
        resources[resourceId] = Resource(caseId, materialClass, ciphertextHash, true);
        emit ResourceRegistered(resourceId, caseId, materialClass, ciphertextHash, authorityId);
    }

    function grantAccess(
        bytes32 resourceId,
        bytes32 persona,
        bytes32 readerRole,
        bytes32 purpose,
        uint64 expiresAt,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        _grantAccess(resourceId, persona, readerRole, purpose, expiresAt, roleKey, authorityId);
    }

    /// @notice Atomically configures ordinary leases, independently checking each resource's application authority.
    function grantAccessMany(GrantInput[] calldata input, bytes32 roleKey, bytes32 authorityId) external {
        if (input.length == 0 || input.length > MAX_GRANTS) revert AVACoreTypes.InvalidState(input.length);
        for (uint256 i; i < input.length; ++i) {
            GrantInput calldata item = input[i];
            _grantAccess(
                item.resourceId, item.persona, item.readerRole, item.purpose, item.expiresAt, roleKey, authorityId
            );
        }
    }

    function _grantAccess(
        bytes32 resourceId,
        bytes32 persona,
        bytes32 readerRole,
        bytes32 purpose,
        uint64 expiresAt,
        bytes32 roleKey,
        bytes32 authorityId
    ) private {
        Resource storage resource = _resource(resourceId);
        CaseRecord storage caseRecord = cases[resource.caseId];
        _authorise(caseRecord.appId, roleKey, GRANT_ACCESS, authorityId);
        _readerValues(persona, readerRole, purpose);
        Rule storage rule = policyRules[caseRecord.policyId][_ruleKey(resource.materialClass, readerRole, purpose)];
        if (rule.allocationExecutor != address(0)) revert AVACoreTypes.InvalidState(uint256(resourceId));
        Membership storage member = memberships[_memberKey(resource.caseId, persona, readerRole)];
        if (
            !resource.active || !policies[caseRecord.policyId].active || rule.phaseMask == 0
                || member.expiresAt <= block.timestamp || expiresAt <= block.timestamp || expiresAt > member.expiresAt
                || uint256(expiresAt) - block.timestamp > rule.maxLeaseSeconds
        ) revert AVACoreTypes.InvalidState(uint256(resourceId));
        // Future-phase leases may be staged, but canAccess always enforces the current phase.
        bytes32 grantKey = _grantKey(resourceId, persona, readerRole, purpose);
        ++grantRevisions[grantKey];
        grants[grantKey] = Grant(expiresAt, member.generation, address(0), 0);
        emit AccessConfigured(resourceId, persona, readerRole, purpose, expiresAt, member.generation, authorityId);
    }

    /// @notice Only the immutable rule executor may apply an allocated protected lease.
    /// @dev A controller permission cannot substitute for the exact executor, current phase,
    /// membership generation or tuple revision approved in the request parameters.
    function grantAllocatedAccess(
        uint256 requestId,
        bytes32 resourceId,
        bytes32 persona,
        bytes32 readerRole,
        bytes32 purpose,
        uint64 expiresAt,
        uint256 expectedMembershipGeneration,
        uint256 expectedGrantRevision
    ) external {
        Resource storage resource = _resource(resourceId);
        CaseRecord storage caseRecord = cases[resource.caseId];
        _readerValues(persona, readerRole, purpose);
        Rule storage rule = policyRules[caseRecord.policyId][_ruleKey(resource.materialClass, readerRole, purpose)];
        Membership storage member = memberships[_memberKey(resource.caseId, persona, readerRole)];
        bytes32 grantKey = _grantKey(resourceId, persona, readerRole, purpose);
        if (
            requestId == 0 || msg.sender != rule.allocationExecutor || !resource.active
                || !policies[caseRecord.policyId].active || (rule.phaseMask & (uint32(1) << caseRecord.phase)) == 0
                || member.expiresAt <= block.timestamp || expiresAt <= block.timestamp || expiresAt > member.expiresAt
                || uint256(expiresAt) - block.timestamp > rule.maxLeaseSeconds
                || member.generation != expectedMembershipGeneration
                || grantRevisions[grantKey] != expectedGrantRevision
        ) revert AVACoreTypes.InvalidState(requestId);
        ++grantRevisions[grantKey];
        grants[grantKey] = Grant(expiresAt, member.generation, msg.sender, requestId);
        emit AccessConfigured(resourceId, persona, readerRole, purpose, expiresAt, member.generation, bytes32(0));
    }

    function revokeAccess(
        bytes32 resourceId,
        bytes32 persona,
        bytes32 readerRole,
        bytes32 purpose,
        bytes32 roleKey,
        bytes32 authorityId
    ) external {
        Resource storage resource = _resource(resourceId);
        _authorise(cases[resource.caseId].appId, roleKey, GRANT_ACCESS, authorityId);
        _readerValues(persona, readerRole, purpose);
        bytes32 grantKey = _grantKey(resourceId, persona, readerRole, purpose);
        ++grantRevisions[grantKey];
        Grant storage grant = grants[grantKey];
        grant.expiresAt = 0;
        emit AccessConfigured(resourceId, persona, readerRole, purpose, 0, grant.membershipGeneration, authorityId);
    }

    function deactivateResource(bytes32 resourceId, bytes32 roleKey, bytes32 authorityId) external {
        Resource storage resource = _resource(resourceId);
        _authorise(cases[resource.caseId].appId, roleKey, REGISTER_RESOURCE, authorityId);
        if (!resource.active) revert AVACoreTypes.InvalidState(uint256(resourceId));
        resource.active = false;
        emit ResourceDeactivated(resourceId, authorityId);
    }

    function deactivatePolicy(uint256 policyId, bytes32 roleKey, bytes32 authorityId) external {
        Policy storage policy = _policy(policyId);
        _authorise(policy.appId, roleKey, MANAGE_POLICY, authorityId);
        if (!policy.active) revert AVACoreTypes.InvalidState(policyId);
        policy.active = false;
        emit PolicyDeactivated(policyId, authorityId);
    }

    function canAccess(bytes32 resourceId, bytes32 persona, bytes32 readerRole, bytes32 purpose)
        external
        view
        returns (bool)
    {
        Resource storage resource = resources[resourceId];
        if (!resource.active) return false;
        CaseRecord storage caseRecord = cases[resource.caseId];
        if (!policies[caseRecord.policyId].active) return false;
        Rule storage rule = policyRules[caseRecord.policyId][_ruleKey(resource.materialClass, readerRole, purpose)];
        if ((rule.phaseMask & (uint32(1) << caseRecord.phase)) == 0) return false;
        Membership storage member = memberships[_memberKey(resource.caseId, persona, readerRole)];
        Grant storage grant = grants[_grantKey(resourceId, persona, readerRole, purpose)];
        if (
            block.timestamp >= member.expiresAt || block.timestamp >= grant.expiresAt
                || grant.membershipGeneration != member.generation
        ) return false;
        if (rule.allocationExecutor == address(0)) return true;
        if (grant.allocationExecutor != rule.allocationExecutor || grant.requestId == 0) return false;
        try IAVAGovernedDisclosure(grant.allocationExecutor).isGrantCurrent(grant.requestId) returns (bool current) {
            return current;
        } catch {
            return false;
        }
    }

    function isMember(bytes32 caseId, bytes32 persona, bytes32 readerRole) external view returns (bool) {
        return block.timestamp < memberships[_memberKey(caseId, persona, readerRole)].expiresAt;
    }

    function membershipDeadline(bytes32 caseId, bytes32 persona, bytes32 readerRole) external view returns (uint64) {
        return memberships[_memberKey(caseId, persona, readerRole)].expiresAt;
    }

    function membershipGeneration(bytes32 caseId, bytes32 persona, bytes32 readerRole) external view returns (uint256) {
        return memberships[_memberKey(caseId, persona, readerRole)].generation;
    }

    /// @notice Every grant and revocation advances this tuple's approval fence, including repeated revocations.
    function grantRevision(bytes32 resourceId, bytes32 persona, bytes32 readerRole, bytes32 purpose)
        external
        view
        returns (uint256)
    {
        return grantRevisions[_grantKey(resourceId, persona, readerRole, purpose)];
    }

    /// @notice Retained allocation history; revocation closes access without erasing its basis.
    /// @dev Routine grants return zero values. A missing executor effect fails closed with zero hash.
    function accessBasis(bytes32 resourceId, bytes32 persona, bytes32 readerRole, bytes32 purpose)
        external
        view
        returns (address executor, uint256 requestId, bytes32 effectHash)
    {
        Grant storage grant = grants[_grantKey(resourceId, persona, readerRole, purpose)];
        executor = grant.allocationExecutor;
        requestId = grant.requestId;
        if (executor == address(0)) return (address(0), 0, bytes32(0));
        try IAVAGovernedDisclosure(executor).grantEffectHash(requestId) returns (bytes32 hash) {
            effectHash = hash;
        } catch {}
    }

    /// @notice Upper bound for an off-chain delivery service's wall-clock check.
    /// @dev canAccess must also pass; a future deadline alone grants no access.
    function accessDeadline(bytes32 resourceId, bytes32 persona, bytes32 readerRole, bytes32 purpose)
        external
        view
        returns (uint64)
    {
        Resource storage resource = resources[resourceId];
        Membership storage member = memberships[_memberKey(resource.caseId, persona, readerRole)];
        Grant storage grant = grants[_grantKey(resourceId, persona, readerRole, purpose)];
        if (grant.membershipGeneration != member.generation) return 0;
        return member.expiresAt < grant.expiresAt ? member.expiresAt : grant.expiresAt;
    }

    function resourceContext(bytes32 resourceId)
        external
        view
        returns (
            bytes32 appId,
            bytes32 caseId,
            uint256 policyId,
            bytes32 materialClass,
            bytes32 ciphertextHash,
            bool active
        )
    {
        Resource storage resource = _resource(resourceId);
        CaseRecord storage caseRecord = cases[resource.caseId];
        return (
            caseRecord.appId,
            resource.caseId,
            caseRecord.policyId,
            resource.materialClass,
            resource.ciphertextHash,
            resource.active
        );
    }

    function caseContext(bytes32 caseId) external view returns (bytes32 appId, uint256 policyId, uint8 phase) {
        CaseRecord storage caseRecord = _case(caseId);
        return (caseRecord.appId, caseRecord.policyId, caseRecord.phase);
    }

    function policyContext(uint256 policyId) external view returns (bytes32 appId, bool active) {
        Policy storage policy = _policy(policyId);
        return (policy.appId, policy.active);
    }

    function getPolicyRules(uint256 policyId) external view returns (Rule[] memory) {
        return _policy(policyId).rules;
    }

    function _authorise(bytes32 appId, bytes32 roleKey, bytes32 action, bytes32 authorityId) private view {
        if (appId == bytes32(0) || roleKey == bytes32(0) || authorityId == bytes32(0)) {
            revert AVACoreTypes.EmptyValue();
        }
        AUTHORITY_MATRIX.requireAuthorisedSubject(msg.sender, appId, roleKey, action, authorityId);
    }

    function _policy(uint256 policyId) private view returns (Policy storage policy) {
        policy = policies[policyId];
        if (policy.appId == bytes32(0)) revert AVACoreTypes.UnknownReference(policyId);
    }

    function _case(bytes32 caseId) private view returns (CaseRecord storage caseRecord) {
        caseRecord = cases[caseId];
        if (caseRecord.appId == bytes32(0)) revert AVACoreTypes.UnknownReference(uint256(caseId));
    }

    function _resource(bytes32 resourceId) private view returns (Resource storage resource) {
        resource = resources[resourceId];
        if (resource.caseId == bytes32(0)) revert AVACoreTypes.UnknownReference(uint256(resourceId));
    }

    function _readerValues(bytes32 first, bytes32 second, bytes32 third) private pure {
        if (first == bytes32(0) || second == bytes32(0) || third == bytes32(0)) revert AVACoreTypes.EmptyValue();
    }

    function _ruleKey(bytes32 materialClass, bytes32 readerRole, bytes32 purpose) private pure returns (bytes32) {
        return keccak256(abi.encode(materialClass, readerRole, purpose));
    }

    function _memberKey(bytes32 caseId, bytes32 persona, bytes32 readerRole) private pure returns (bytes32) {
        return keccak256(abi.encode(caseId, persona, readerRole));
    }

    function _grantKey(bytes32 resourceId, bytes32 persona, bytes32 readerRole, bytes32 purpose)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(resourceId, persona, readerRole, purpose));
    }
}
