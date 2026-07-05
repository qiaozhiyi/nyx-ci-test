# Nyx Code Audit Guidelines

You are auditing a specific subsystem of the **Nyx C2 Framework**.
Your audit MUST focus on:

1. **Security Vulnerabilities & Bugs**:
   - Out-of-bounds reads/writes, unsafe code violations, buffer overflows/underflows in manual parsing.
   - Race conditions, memory leaks, panics in production/server paths.
   - Logic bugs, access control bypasses in control APIs.

2. **Cryptographic Integrity & Anti-Replay**:
   - Weaknesses in the key exchange, ephemeral key usage, or AEAD decryption.
   - Faults in the anti-replay logic (e.g. counter tracking).
   - Randomness quality (PRNG seeding, thread safety).

3. **Detection, Signature, & Attribution/Traceability**:
   - Distinctive or hardcoded string literals, user agents, paths, registry keys, names that EDR/AV can signature or blue teams can trace back to operators.
   - Flaws in sandbox evasion or environmental probes.
   - Artifacts left in memory, unmasked memory regions, or telltale stack frames.

4. **Design Flaws & Robustness**:
   - Multi-operator synchronization issues, file system traversal vulnerabilities.
   - Missing check/bounds on input data lengths.

Ensure you audit **every line** of your assigned target files.
