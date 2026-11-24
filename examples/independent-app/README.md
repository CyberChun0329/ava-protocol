# Independent WorkOrder consumer

This small management app closes a synthetic work order after requester evidence,
inspector recognition and manager Allocation. Its own Solidity application module
and effect adapter import only the installed `@ava-protocol/contracts` package.
There are no tokens, payments, front end, existing sample-app imports or Base calls.

Build the matching preview from the source root with `npm run pack:preview`.
Then follow the README in the extracted preview. The verifier uses a new consumer directory, installs
the versioned archives, checks public imports, and runs both the cost profiles
and rule lifecycle on a disposable Anvil chain (31337).

The installed Core bootstrap runs before the consumer-owned installer. The public
SDK deployment exporter creates `public-deployment.json` from both sets of actual
Foundry receipts and the consumer's newly compiled artifacts. `verifyInstallation`
checks its declared app, modules, actors, permissions and correction bindings.
The consumer pairs the named WorkOrder module from its deployment receipt with
the capability the app requires and declares the actor and action requirements
itself. It passes an intentionally wrong module address and canonical subject
to the same SDK check. Both mismatches are reported, and the corrected
declaration passes at the same block, without granting anything or sending a
transaction. `installationDiagnostics` records the result.

`InstallWorkOrder.run(...)` keeps the fresh-policy installation. When the same Core
already has the two stateless defaults, `runWithPolicies(..., corePolicy,
extensionPolicy)` accepts their explicit addresses and uses the package's
`AVADefaultPolicies.requireExact` to check both runtime hashes before broadcast.
The application module, ledger and app-bound request policy are still new. The
public exporter receives the same explicit `defaultPolicies` addresses.

The consumer compares fresh and reused installations from the same local snapshot,
after compiling both entry points. It rejects wrong addresses and swapped policy
types before completing the reused installation and full workflow. Policy setup,
the reverted fresh-install comparison branch and the actual reused installation
are counted separately: the first app still pays to create the two shared defaults.
Local command elapsed times include simulation/broadcast and are not network
inclusion or finality estimates.

The default check also rehearses a send interruption on the reused branch. It
replays the original signed installation sequence on the pre-install Anvil
snapshot and stops before the final business permission batch. Readiness must
report the ten missing grants from the consumer's declared requirements. The
consumer then explicitly submits the held transaction and exports the same
installation identity from the resumed chain's receipts. The snapshot and replay
are confined to this local fixture.

The app's delegated administrator hands over to a successor through the existing
two-step transfer. `verifyInstallation` detects an unwanted inspector Allocation
grant before the handover. Once the successor accepts, they remove the grant and
the previous delegate loses authority to change it. An injected RPC failure
for that permission remains unavailable, and a healthy read at the same block
confirms the repair. The check then runs the ordinary WorkOrder workflow.
These administrative transactions are reported separately from the business and
installation costs.

In the rule lifecycle exercise, the first process
installs and seals a governing workflow, then registers two independently
recognised proposals with the same predecessor. A separate Node process uses the
installed SDK and the handed-off terms to verify and activate one proposal. It
rejects changed metadata, reordered modules, replay and the now stale competing
proposal. The output records canonical receipt coordinates and the successor
installation check.

The first process checks that the old installation declaration fails and the
successor declaration passes. The successor closes intake of new WorkOrder
objects. Signing preflight rejects a new object against both the inactive
predecessor and the successor. The successor still admits evidence. A second,
already-approved WorkOrder executes once under its original package, recognition
and Allocation. Fresh correction evidence admitted by both versions supports a
finite finding about the first WorkOrder's completed effect. Its original
recognition, request and receipt remain available unchanged.

The second closure also exercises explicit HTTP recovery. The fixture interrupts
the relay before sending to Anvil. Reading the original key, observing, and repeating ordinary submission under the
same or an alias key leave the approval unconsumed. Recovery rejects different
signed bytes. An explicit recovery with the original bytes reaches
Anvil, but the fixture drops the response. Observation then verifies the same
key, hash, nonce and canonical block. Recovering the confirmed identity sends
no further transaction. `lifecycle-evidence.json` records the result without
including signed bytes in the recovery summary.

This policy closes new object intake. Previously admitted work keeps the rules
that apply to it, including authority, execution and correction checks. The runner
reports governance setup and lifecycle transactions separately. This mode uses
the same disposable chain 31337 and local service as the ordinary check.

All business transactions are caller-signed through the installed SDK and submitted
through the installed local service over actual loopback HTTP. The checks reject
wrong actors, execution before Allocation, revoked manager authority, altered
parameters and repeated execution. A subsequent Effect correction records a finite
claim/use-scope/burden finding and retains the original recognition and effect.
HTTP queries check recognition, request, app-effect and correction projections.

The copied project's `evidence.json` records package hashes, declaration identity,
IDs, original records, correction, checks, and every transaction's gas, fee and
calldata bytes, grouped into Core, shared-policy setup, fresh-install comparison,
actual install and business phases. `policyReuse` records the paired installation
elapsed times and rejected configurations. Logs, broadcasts
and compiled artifacts remain in the same directory for inspection.

The verifier compares three configurations with the same WorkOrder and actors:
 (1) fresh defaults with separate provisional formation
and transition to Challengeable, (2) fresh defaults with combined formation, and
(3) shared defaults with combined formation. The runner compiles once and runs
each branch serially from the same local snapshot taken after Core and shared
default-policy setup. Each branch gets a separate service database and completes
the same recognition, Allocation, execution, correction and HTTP history checks,
including rejected actions followed by lawful completion.

In profile mode, `evidence.json` contains each branch's IDs, assertions, complete
transaction and receipt records, and separate totals for app installation,
normal business operations, corrective review and the permission revoke/restore used by verification. Core
and shared-policy setup are reported once outside the branches. Pairwise deltas
compare combined against split business operations and shared against fresh
installation; shared-policy setup must be accounted for separately when it is
newly required. Reverted branches are alternatives, not costs to add together.
These are synthetic Anvil measurements, not network prices or claims about
additional savings beyond the compared transactions.

This is a local integration fixture with structural policies and synthetic evidence.
It does not establish production policy, physical completion or safety, deployment
on another chain, hosted-service operation, a front end or application readiness.
