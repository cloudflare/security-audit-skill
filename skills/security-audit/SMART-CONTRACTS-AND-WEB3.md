# Smart Contract and Web3 Hunting

#### When to use this file

Reach for this file when the repository contains on-chain program code or tightly coupled off-chain components that hold or move value or authority: Solidity or Vyper contracts, Rust programs for account-based chains, Move modules, bridges, wallets, signers, relayers, keepers, or indexers that feed on-chain decisions. In these targets, deployed code is public and callable by anyone, state is shared and permanent, and a balance or invariant violation has direct financial consequence. Use `CRYPTOGRAPHY-AND-SECRETS.md` for signature and key handling off-chain, `SUPPLY-CHAIN-AND-RELEASE.md` for deployment scripts and dependency trust, and `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` for off-chain relayer or keeper availability.

Pick classes from Phase 1. Split a large target into authorization and initialization, external calls and ordering, value accounting, price and oracle inputs, signatures and message replay, upgrade and storage, and cross-chain messages.

## Core discipline (include in every agent prompt for this domain)

```
- Every external or public function is callable by any address, in any order, with any arguments, and from a contract as well as an account. State the caller capability explicitly: any address, a token holder, a depositor, a role holder, or a contract with callbacks.
- Name the protocol invariant that fails (for example, total shares match assets, balances equal sum of accounts, only the owner can mint, a signature is consumed once). A "vulnerability" with no violated invariant and no loss of value or authority is a note.
- Reason about composability: a caller can be a contract, can use flash-sourced capital in one transaction, can reenter through token hooks, and can order transactions around yours. State which of these your claim needs.
- Local validation uses an in-process test environment with dummy accounts and dummy tokens. Never fork a live network, never use a real RPC endpoint or key, and never interact with a deployed contract or testnet.
- Deployed addresses, owner and admin keys, multisig membership, oracle and parameter settings, and live token behavior are outside the repository. If the decisive fact is a deployed value, use `needs_validation` with the exact on-chain fact for the owner to confirm from their own records.
```

## Authorization and initialization attack classes (subagent_type: `general`)

**Missing or wrong access control**
A privileged function (mint, burn, pause, upgrade, withdraw, set oracle, set fee, set owner) lacks a role check, checks the wrong role, authenticates through `tx.origin` or a caller-controlled value, or can be reached through a sibling function that performs the same state change without the check. In account-model programs, check signer requirements, account ownership, and that supplied accounts are the expected ones.

**Initialization and ownership takeover**
An initializer can be called by anyone, called twice, or left uncalled on an implementation behind a proxy; a constructor-equivalent step sets an owner from an unvalidated argument; or two-step ownership transfer can be hijacked. Check both the proxy and implementation initialization states.

**Account and program substitution**
An account-model program accepts accounts without verifying type, owner, address derivation, or expected relationships, accepts an arbitrary program identifier for a cross-program call, or lets a derived address seed collide across users or roles. Verify each account against the state it should be bound to.

## External calls and ordering attack classes (subagent_type: `general`)

**Reentrancy, including cross-function and read-only**
State is updated after an external call, a guard covers one function but not a sibling reading shared state, a view function is consumed by another protocol while state is mid-update, or a token or receiver hook gives control to the caller. Establish the exact state read after control returns and the concrete invariant it breaks.

**Unchecked and unsafe external interaction**
Low-level call results are ignored, a token that returns no value or false is treated as success, arbitrary call data or target is attacker-controlled, `delegatecall` targets a caller-influenced address, or a loop over callers lets one reverting receiver block everyone.

**Denial of service through state or gas**
An unbounded loop over user-growable storage, a withdrawal that depends on every recipient succeeding, or a function whose cost grows with attacker-controlled state can brick a critical path. Require a concrete critical function that becomes unusable and a permissionless way to cause it.

## Value accounting attack classes (subagent_type: `general`)

**Share-price and first-depositor manipulation**
A vault or pool derives share price from a balance that an outside transfer can change, allows a tiny initial deposit followed by a donation to inflate price, or rounds in the direction that favors the actor. Check rounding direction for mint, redeem, deposit, and withdraw separately, and what protects the first deposit.

**Token behavior assumptions**
Accounting assumes the amount received equals the amount sent, ignores transfer fees or rebasing balances, assumes 18 decimals, trusts a token's reported balance, or treats a token with hooks as inert. Compare the accounting variable with what the contract actually receives.

**Invariant breaks through composition**
A function is safe in isolation but combining deposit, borrow, liquidate, and withdraw in one transaction breaks a solvency or collateral invariant, especially with flash-sourced capital. Write the invariant and attempt the shortest sequence that violates it in a local test.

**Numeric precision and casting**
Unchecked blocks, narrowing casts, scale mismatches between values, division before multiplication, and release-mode wraparound in non-checked languages change amounts. Verify the range the inputs can actually take.

## Price, oracle, and economic attack classes (subagent_type: `general`)

**Manipulable or stale price input**
A price is read from a spot reserve ratio that one transaction can move, a feed is used without staleness, zero, or round-validity checks, a sequencer or fallback-oracle state is not handled, or a time-weighted average uses a window too short for the value at risk. State what it costs an actor to move the price relative to what moving it gains, as a source-level argument.

**Missing slippage, deadline, and ordering protection**
Swaps, liquidations, or auctions accept any output, have no deadline, or can be sandwiched or front-run because the profit-relevant parameter is caller-chosen and unprotected. Report only where the protocol, not just the caller's own trade, loses value or the protocol claims protection.

**Governance and voting manipulation**
Voting weight can be borrowed for a block, delegation can be changed after a snapshot, quorum or proposal thresholds can be gamed, or a timelock can be bypassed through an alternate execution path.

## Signatures, replay, and cross-chain attack classes (subagent_type: `general`)

**Signature validation and replay**
Signed messages omit a nonce, chain identifier, contract address, or domain separator; a recovered zero address is treated as valid; a signature can be malleated to a second valid form that bypasses a used-signature check; or one signature authorizes multiple actions. Check what is signed versus what is executed.

**Permit and meta-transaction trust**
A relayer or forwarder lets the signer be spoofed, a permit can be front-run to break a flow, or `msg.sender` is read inside a forwarded call where the original sender is required.

**Cross-chain and bridge message authentication**
A message handler trusts the sender chain, sender address, or message identifier without validating the verifier, allows replay of the same message, or lets a failed message be re-executed with different parameters. Establish who the verifier is and what it signs.

## Upgrade and storage attack classes (subagent_type: `general`)

**Proxy and storage-layout hazards**
An upgrade changes storage ordering, a proxy and implementation use colliding slots, an upgrade authorization function is missing or reachable, or an implementation can be destroyed or initialized by an outsider. Compare the old and new layouts and the upgrade path.

**Admin power and timelock gaps**
A single key can change critical parameters, drain funds, or upgrade immediately where documentation promises delay or limits. Source can show the power; the actual holder is a deployed fact and belongs in `needs_validation`.

## Universal moves (apply across the above)

- List every external and public function with its caller restriction, state it reads, state it writes, external calls it makes, and events it emits. Mark each that moves value or authority.
- Write the system's core invariants first, then try to violate each with the shortest sequence of calls in a local test, including contract callers and single-transaction multi-step sequences.
- Diff sibling functions (deposit/mint, withdraw/redeem, transfer/transferFrom, pause/emergency) for equivalent checks, not just presence.
- Read the test suite for invariants the authors checked; the untested invariant is often where the defect lives.
- Compare every assumption about an external token, oracle, or protocol with what the code verifies about it.

## Validation rules (apply before reporting ANY finding here)

1. State the caller capability, the violated invariant, and the concrete loss of value, authority, or availability. Gas optimizations, style, and best-practice deviations are not findings.
2. Demonstrate with a local, in-process test using dummy accounts and dummy tokens. Do not use a forked network, real keys, or any deployed contract, and do not produce tooling aimed at a deployed system.
3. Separate source-visible logic from deployed configuration. Owners, multisigs, oracle addresses, fee values, and live token behavior are `needs_validation` with the exact fact to check.
4. Do not claim a profit-based attack without a source-level argument that the cost to the actor is less than the gain; do not stretch a limited accounting error into total loss.
5. For reentrancy, show the control transfer and the exact stale state used after it. If a guard, ordering, or token behavior prevents it, reject.
6. Return `confirmed` only with a complete source trace and a bounded local result. Return `needs_validation` with the exact deployed value, upgrade state, parameter, or token behavior required.
