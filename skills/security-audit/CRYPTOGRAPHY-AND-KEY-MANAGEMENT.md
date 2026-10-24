# Cryptography and Key-Management Hunting

#### When to use this file

Reach for this file when the target implements, configures, or relies on cryptographic primitives, key lifecycle, encryption at rest or in transit, digital signatures, password hashing, MAC verification, cryptographic token generation, or certificate and TLS trust. This domain follows keys and cryptographic parameters through generation, derivation, usage, storage, rotation, and revocation.

Use this with `ATTACK-CLASSES.md`: access-control and business-logic reviews ask whether an authenticated principal has authority to perform an operation; this file asks whether the cryptographic mechanisms protecting data confidentiality, integrity, authenticity, or identity can be broken, bypassed, or forged. Use `WEB-PROTOCOL-AND-AUTH.md` for HTTP session cookies, CSRF, and federated identity flows (OAuth/OIDC/SAML); use `PROTOCOLS-RPC-AND-MESSAGING.md` for protocol wire framing; use `CLOUD-AND-DEPLOYMENT.md` for cloud provider IAM and hosted KMS configuration; and use this file for cryptographic algorithms, cipher modes, nonce/IV lifecycle, randomness, signatures, MACs, constant-time comparison, TLS client configuration, and secret storage.

Pick classes from Phase 1 and split large targets by symmetric ciphers and AEAD, randomness and key derivation, signatures and MACs, TLS and certificate validation, and secret storage and key lifecycle.

## Core discipline (include in every agent prompt for this domain)

```
- A cryptographic finding requires an exploitable mathematical, parameter, or implementation flaw in a security-relevant path. Deprecation alone without an accepted weak parameter or broken guarantee is a hardening note.
- Verify both sides of the contract: generation, parameter selection, transport, verification/decryption, and key lifecycle. Nonce reuse, static IVs, missing MACs, and predictable seeds must be traced to observable state recovery, forgery, or decryption.
- Signature and MAC checks must verify before use. Algorithms, curves, key lengths, and key selectors must be bound server-side rather than accepted from untrusted inputs.
- Secrets, private keys, and symmetric keys must remain inaccessible to lower-trust principals. Verify storage, in-memory zeroing, log sanitization, and scope separation.
- Use `confirmed` only for complete source evidence and bounded local cryptographic fixtures. Use `needs_validation` when KMS policy, HSM state, deployed certificate authority, or secret values are required but not in-repo.
```

## Symmetric cipher and mode attack classes (subagent_type: `general`)

**ECB mode and unauthenticated encryption**
Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving data patterns and enabling block rearrangement or replay without detection. CBC mode without an authenticating MAC (or using MAC-then-decrypt) allows ciphertext malleability, bit-flipping, and padding oracle attacks. Contrast with modern Authenticated Encryption with Associated Data (AEAD) constructions like AES-GCM or ChaCha20-Poly1305. Require a path where attacker-influenced ciphertext is decrypted and oracle behavior or tampered blocks alter authorization, decrypted fields, or application flow.

**Nonce and IV reuse in stream ciphers and AEAD**
Reusing a nonce under the same key in AES-GCM, AES-CCM, or ChaCha20-Poly1305 destroys authenticity guarantees—enabling derivation of the GHASH/authenticator key and arbitrary message forgery—and leaks the XOR sum of the plaintexts. In CBC mode, predictable, sequential, or static initialization vectors (IVs) allow chosen-plaintext attacks. Trace nonce and IV generation across all callers: verify whether nonces repeat on system restart, across worker processes or concurrent threads, through counter overflow, or when derived from static message attributes.

**Weak or deprecated symmetric algorithms**
Legacy ciphers such as DES, 3DES, RC4, or ciphers with 64-bit block sizes (vulnerable to birthday-bound collision attacks like Sweet32) used for bulk data protection. Verify whether the weak cipher is actively chosen and used on untrusted data where small key spaces or block collisions lead to practical plaintext extraction or key recovery. Bare presence of a legacy cipher suite in a library without active selection is a hardening note.

## Randomness, key derivation, and token generation attack classes (subagent_type: `general`)

**Predictable and non-cryptographic randomness**
Using non-cryptographic pseudo-random number generators (such as `Math.random()`, `rand()`, `random.random()`, or linear congruential generators) for security-sensitive values: session identifiers, password reset tokens, API keys, CSRF tokens, cryptographic nonces/IVs, salts, or private key generation. Confirm that an observer or unauthenticated client can reconstruct the generator state, predict future or past outputs, and forge or guess tokens within realistic attempt bounds.

**Weak password hashing and inadequate KDF work factors**
Storing user credentials using plain cryptographic hashes (MD5, SHA-1, SHA-256), unsalted digests, or single-iteration hashes vulnerable to precomputed rainbow tables and high-speed GPU dictionary attacks. In systems using memory-hard or iterated KDFs (bcrypt, Argon2, PBKDF2, scrypt), review iteration counts and memory parameters against modern operational thresholds. Trace whether salts are globally static or hardcoded rather than cryptographically random and unique per account.

**Broken key derivation and context mixing**
Deriving operational keys (e.g., separate encryption and authentication keys, or keys for different tenants or protocols) from a shared root secret without a cryptographically sound Key Derivation Function (such as HKDF) and domain separation strings. Truncating raw hashes, concatenating passwords with static strings, or reusing one symmetric key across multiple incompatible cryptographic modes allows cross-context substitution attacks and key recovery.

## Asymmetric cryptography, signatures, and MAC attack classes (subagent_type: `general`)

**Signature verification omission and decode-without-verify**
Unpacking, parsing, or trusting assertions, JWTs, SAML responses, CMS/PKCS#7 envelopes, or signed firmware/configuration objects before or without verifying their cryptographic signatures. Review error handling: check whether signature failures log a warning but proceed with processing, or if fallback branches accept unverified payloads. For token systems, review algorithm enforcement to ensure `alg: "none"` or unapproved algorithms are rejected at the server level.

**Algorithm confusion and untrusted key selector injection**
In token and signature verification, accepting algorithm headers from untrusted input that cause the verifier to treat an asymmetric public key as a symmetric HMAC secret, verifying an attacker-signed token. In public-key verification protocols, allowing untrusted headers (`kid`, `jku`, `jwk`, `x5u`) to specify arbitrary key URLs, untrusted certificates, or local file paths via directory traversal without an explicit server-side trust allowlist.

**Missing or broken MAC verification**
Constructing hybrid encryption schemes with unauthenticated ciphertext (Encrypt-and-MAC rather than Encrypt-then-MAC, or omitting the MAC entirely), or failing to bind ciphertext, initialization vectors, and authenticated metadata under the MAC tag. Confirm whether tampered ciphertext is processed before MAC verification or whether altered metadata is accepted.

**Timing side-channels on secret comparison**
Comparing secrets, HMAC digests, signatures, password hashes, or session tokens using standard variable-time comparison operators (`==`, `!=`, `===`, `strcmp`, `memcmp`) that short-circuit on the first mismatched byte. An attacker measuring execution time variations across network or local boundaries can infer secret bytes sequentially. Confirm that comparisons on secret material use constant-time functions (e.g., `crypto.timingSafeEqual`, `hmac.compare_digest`).

**Malleability and weak public-key parameters**
RSA encryption with PKCS#1 v1.5 padding vulnerable to Bleichenbacher padding oracles in decryption, small RSA keys (< 2048 bits), static Diffie-Hellman parameters with small subgroups, or ECDSA implementations that reuse or leak bits of the per-message secret `k` (allowing complete private key extraction). In elliptic curve operations, verify that received public points are validated against the curve equation and generator order to prevent invalid curve attacks.

## TLS, certificate validation, and transport security attack classes (subagent_type: `general`)

**Disabled certificate and hostname validation**
TLS client configurations or HTTP clients that disable certificate verification (`InsecureSkipVerify: true`, `rejectUnauthorized: false`, trust managers that accept all certificates without checking the trust chain), or that disable hostname verification (`setHostnameVerifier(ALLOW_ALL)`). An attacker positioned on the local network or upstream path can present a self-signed certificate and intercept or alter sensitive traffic. Verify that the bypass is present in operational client paths, not in isolated unit tests.

**Weak TLS configuration and cipher suite downgrade**
Protocols or server listeners configured to accept obsolete TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) or weak cipher suites (NULL, export ciphers, RC4, single DES, or CBC-mode ciphers without Encrypt-then-MAC). Confirm whether an active attacker can negotiate down to a vulnerable cipher suite to decrypt sessions or extract credentials.

## Secret management and key lifecycle attack classes (subagent_type: `general`)

**Hardcoded cryptographic keys and embedded secrets**
Cryptographic private keys, symmetric keys, HMAC secrets, or KMS credentials embedded directly in source code, configuration templates, or default environment files. Confirm whether the hardcoded key is used to protect production data, encrypt user state, or sign tokens, or whether identical default keys ship in distributed software binaries.

**Insecure key storage, permissions, and serialization**
Private keys or symmetric keys stored in world-readable files, unencrypted disk caches, client-side bundles, or browser storage. Emitting key material into logs, debug traces, metrics, exception backtraces, or diagnostic endpoints. Failure to zero or overwrite sensitive key material in memory after use where the runtime provides explicit memory management controls.

**Key rotation and multi-version retirement failure**
Cryptographic subsystems that lack key versioning, preventing rotation of compromised keys without breaking all existing encrypted data or active sessions. Conversely, systems that maintain deprecated or compromised keys indefinitely without an expiration or revocation cut-off, allowing revoked keys to continue decrypting new payloads or forging valid signatures.

## Universal moves (apply across the above)

- Map the complete cryptographic lifecycle: key generation/import -> key derivation/expansion -> algorithm and mode execution -> transport/storage -> verification/decryption -> rotation/revocation. Compare normal, error, retry, and migration branches.
- Identify all secret comparison points. Verify whether comparisons between attacker-supplied data and cryptographic secrets, tokens, or MACs use constant-time comparison primitives rather than short-circuiting equality checks.
- Audit nonce and IV sources: trace whether nonces for AES-GCM, AES-CCM, and ChaCha20 are cryptographically guaranteed to be unique and never repeat across reboots, multiple container instances, or thread executions under the same key.
- Verify algorithm and key pinning: check whether the verification logic enforces an explicit, server-controlled allowlist of acceptable algorithms, key lengths, and trusted key identifiers rather than trusting caller-supplied token headers.
- Test algorithm confusion and parameter tampering with local fixtures: verify locally that `alg: "none"`, swapped HMAC/RSA algorithms, flipped ciphertext bits in AEAD, or truncated signatures are rejected by the target code.

## Validation rules (apply before reporting ANY finding here)

1. Name the exact source file and line where the cryptographic operation, parameter selection, or key handling occurs, naming the specific primitive, algorithm, and affected security property (confidentiality, integrity, authenticity, or non-repudiation).
2. For nonce reuse or static IV claims, prove that the same key and nonce/IV pair can coincide across two distinct messages or operations, and state the exact observable result (keystream reuse, GHASH key recovery, or chosen-plaintext oracle).
3. For randomness or token predictability findings, identify the PRNG implementation and seed source, and demonstrate how an attacker reconstructs state or generates valid tokens within practical computational bounds.
4. For signature, MAC, or token validation bypasses, prove that the verification logic accepts a forged, tampered, or `none`-algorithm payload in a bounded local test harness, and confirm that upstream frameworks or gateway layers do not reject the input first.
5. For TLS or certificate validation bypasses, prove the flaw exists in reachable production client code rather than isolated test helpers, and verify that default framework settings do not override the insecure option.
6. Return `confirmed` only with complete source lineage and bounded local test demonstration of the cryptographic flaw. Return `needs_validation` when external KMS policies, HSM key protection, physical entropy sources, or operational deployment secrets cannot be determined from source code alone.
