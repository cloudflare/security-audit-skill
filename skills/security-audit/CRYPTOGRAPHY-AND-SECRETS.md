# Cryptography and Secret Handling Hunting

#### When to use this file

Reach for this file when the repository implements or configures cryptography rather than merely calling TLS through a managed proxy: encryption at rest or in transit, signatures and MACs, password storage, key derivation, token or ID generation, certificate validation, key management, custom protocols, or secret loading and rotation. `ATTACK-CLASSES.md` carries a short "Cryptography and secrets" prompt; this file is the depth pass for targets where a cryptographic invariant is itself a trust boundary. Use `WEB-PROTOCOL-AND-AUTH.md` for JWT/OAuth/SAML claim binding, `SUPPLY-CHAIN-AND-RELEASE.md` for signing and update trust, and `DATA-ISOLATION-AND-LIFECYCLE.md` for key-per-tenant scoping.

Pick classes from Phase 1. Split a large target into primitive and mode use, randomness and identifiers, verification paths, key hierarchy and password storage, transport and protocol handshakes, and secret lifecycle.

## Core discipline (include in every agent prompt for this domain)

```
- Name the attacker capability before judging an algorithm: observe ciphertext, choose plaintext, submit forged tags or signatures, replay messages, read logs, or read client bundles. An old or weak primitive with no attacker-reachable role is hardening, not a finding.
- Check the claimed property, not the algorithm name: confidentiality, integrity, authenticity, freshness, context binding, or unpredictability. Many defects use a strong primitive that provides the wrong property.
- Read every verification site for the failure path. A verify call whose result is ignored, caught as success, compared loosely, or skipped on an error branch is the finding, not the primitive.
- Identify what bytes are authenticated versus what bytes are later used. Parse-then-verify, verify-then-reparse, and canonicalization differences create two interpretations of one message.
- Do not run brute force, cracking, or key-recovery work. Derive work factors and key sizes from source parameters and known-answer tests with dummy keys.
- Use `confirmed` only when a local harness with dummy keys shows the invalid input accepted, the reused value reachable, or the secret exposed. Use `needs_validation` when the decisive fact is a deployed key, certificate, HSM policy, or provider default.
```

## Primitive and mode attack classes (subagent_type: `general`)

**Nonce and IV reuse in AEAD or stream modes**
AES-GCM, ChaCha20-Poly1305, CTR, or similar modes use a nonce that can repeat under one key: a fixed value, a counter reset on restart, a counter shared across instances without partitioning, a random nonce too short for the message volume, or a nonce derived from attacker-influenced data. Establish the key scope, the nonce source, and a concrete path that produces two encryptions under the same key and nonce.

**Unauthenticated or malleable encryption**
CBC, CTR, or ECB is used without a verified MAC, MAC-then-encrypt checks run in a way that exposes padding or error differences, or ciphertext is accepted and decrypted before authentication. Check whether an attacker can modify ciphertext and observe either a changed plaintext, an error oracle, or a behavioral difference. ECB matters when attacker-visible or attacker-influenced structured data is encrypted.

**Missing context binding**
A valid ciphertext, MAC, or signature for one purpose is accepted for another: another tenant, record, field, protocol message type, key purpose, or version. Check associated data, domain-separation labels, and whether a ciphertext can be moved between rows or users and still decrypt.

**Truncation and weak-construction misuse**
Tags are truncated below a safe length, `H(secret || message)` is used as a MAC with a length-extendable hash, an unkeyed hash is used where authentication is required, or a hash of attacker-ambiguous concatenation (`a||b`) is signed so field boundaries are not authenticated.

## Randomness and identifier attack classes (subagent_type: `general`)

**Predictable security values**
Tokens, session identifiers, reset codes, API keys, nonces, salts, or keys come from a non-cryptographic generator, a time-seeded generator, a low-entropy space, or an ID scheme with predictable structure such as time-ordered or sequential identifiers used as bearer capability. Establish the generator, the seeding, the space size, and whether an attacker can observe neighboring outputs.

**Entropy and duplication failures**
A fallback path substitutes weak randomness when the OS source fails, a forked or snapshotted process repeats generator state, or a derived value uses a small domain such as a short numeric code with no attempt limit. Review startup, container-clone, and error-fallback behavior.

## Verification and comparison attack classes (subagent_type: `general`)

**Fail-open verification**
Signature, MAC, certificate, or hash verification result is ignored, treated as truthy when an error object or promise is returned, bypassed on an exception, skipped for a legacy or debug path, or applied to a different byte range than the one consumed. Read the failure branch of every verify call.

**Comparison of secrets**
Secrets, MACs, or tokens are compared with an early-exit or type-coercing comparison where a remote or co-located attacker can measure the difference, or compared after truncation or case-folding that widens the accepted set. Constant-time comparison matters only where timing is attacker-observable; type-coercion and loose-equality acceptance matter everywhere.

**Algorithm and key selection by the attacker**
The algorithm, curve, key identifier, key URL, or certificate is chosen from the message being verified, enabling downgrade, `none`-style acceptance, or substitution of a key the attacker controls. The accepted algorithm and key source must be pinned by the verifier.

**Replay and freshness**
A signed or authenticated message has no nonce, counter, expiry, or audience, or the replay store is per-instance, per-restart, or bypassable through key normalization. Confirm what state the verifier consults and whether a second valid delivery changes security state.

## Key management and password storage attack classes (subagent_type: `general`)

**Password and credential storage**
Passwords are stored with a fast general-purpose hash, no per-user salt, a work factor below current guidance for the algorithm in use, reversible encryption, or a scheme with an input-length quirk such as silent truncation or NUL handling. State the algorithm and parameters from source; do not attempt to crack anything.

**Key reuse and missing domain separation**
One key is used for encryption and authentication, for several purposes, or across tenants and environments, so a capability in one role becomes a capability in another. Review key derivation labels, per-tenant key scoping, and whether test and production keys can be confused.

**Key hierarchy, rotation, and downgrade**
Key versions, rotation, or wrapped data-encryption keys let an attacker select an older or weaker key version, force a fallback, or keep a revoked key valid. Compare rotation, restore, and import paths with the normal path.

**Secrets in source, artifacts, and client bundles**
Private keys, signing secrets, service credentials, or encryption keys appear in source, committed history, build outputs, logs, error responses, URLs, mobile or browser bundles, or environment variables exposed to client code by a framework prefix. A public key, key identifier, or publishable client key is not a secret. Require an actual credential with authority, and note what it unlocks.

## Transport and protocol attack classes (subagent_type: `general`)

**Disabled or incomplete certificate validation**
Verification is turned off, hostname or SAN matching is missing, the trust store is replaced, validation errors are swallowed, or a pinning path falls back to unpinned on failure. Confirm the setting is active in a production path, not a test fixture.

**Custom handshake and key-exchange flaws**
A bespoke protocol lacks transcript binding, authenticates only one side, accepts attacker-supplied group parameters or invalid curve points, lets the peer choose the cipher suite without authentication, or reuses ephemeral keys. Prefer a minimal local harness over reasoning from memory about the construction.

**Signature and asymmetric misuse**
RSA encryption with a decryption-error oracle, signatures over ambiguous serialization, malleable signature acceptance where uniqueness matters, ECDSA nonce reuse or bias, and signature verification that accepts a missing or empty value. Establish which property the consumer relies on.

## Failure behavior and secret lifecycle attack classes (subagent_type: `general`)

**Cryptographic failure falls back to weaker behavior**
Failure to decrypt, verify, or load a key results in plaintext storage, an empty or default key, an unauthenticated mode, or an accepted request. Trace configuration-missing, key-service-unavailable, and parse-error paths.

**Oracles and secret-bearing diagnostics**
Distinct error messages, status codes, or timings reveal padding validity, MAC validity, key existence, or token structure, and secrets or key material appear in logs, crash reports, analytics, or exception messages. Require a lower-trust reader of the output.

## Universal moves (apply across the above)

- Build a table of every secret and key: generator, storage location, purpose, scope, rotation path, and every code site that reads it. Differences between maintained environments need an explanation.
- For each verification site, write the exact bytes verified and the exact bytes later consumed. Any difference is a lead.
- For each nonce, token, or ID, name the source of randomness and the space an attacker would have to search, using only source-visible parameters.
- Diff the normal path with the migration, import, restore, legacy-compatibility, and error-fallback paths for the same cryptographic operation.
- Search for tests that pin known-answer vectors. Missing tests for failure and tamper cases often mark the weak branch.

## Validation rules (apply before reporting ANY finding here)

1. State the attacker capability and the security property that fails. A deprecated algorithm, short key, or missing constant-time compare with no reachable attacker role is a hardening note.
2. For a verification or comparison defect, show a dummy-key harness in which the invalid input is accepted, or the equivalent source-complete trace through the failure branch.
3. For nonce, IV, or randomness reuse, show the concrete reachable path that yields the repeat or the predictable value, and state the consequence the mode actually has. Do not claim key recovery without a bounded local demonstration.
4. For secrets, require a real credential or key with authority. Exclude public identifiers, publishable keys, documented placeholders, and test-only fixtures that are not shipped or accepted in a production path.
5. Never brute-force, crack, or search for keys. Do not use a real credential, certificate, or key even if one is found in source. Record only that it exists and what it appears to authorize.
6. Return `confirmed` only with a complete trace and a bounded local result. Return `needs_validation` with the exact deployed key, certificate, HSM or KMS policy, provider default, or environment value required.
