# CRCS — Collusion-Resistant Credential System

## Design Document — Phase I Submission

> **ISI Kolkata × Fortytwo Labs — ZKP-Based Multi-System Attribute Verification Hackathon**
> **Team Name**: _[YOUR TEAM NAME]_
> **Date**: February 2026

---

## 1. Abstract

We present the **Collusion-Resistant Credential System (CRCS)**, a zero-knowledge proof-based framework for multi-system attribute verification that provides strong unlinkability and collusion resistance guarantees. Unlike traditional credential systems (e.g., BBS+ signatures), CRCS uses additive secret sharing combined with Poseidon commitments and Groth16 proofs to enable attribute predicate verification (e.g., "age > 18", "income > 5L") across multiple independent verifiers, while ensuring that even colluding verifiers cannot link proofs to the same credential holder.

Our system achieves:
- **Computational unlinkability**: Fresh randomness per proof session ensures no two proofs are algebraically linkable
- **Collusion resistance**: k colluding verifiers learn exactly k independent YES/NO values — no cross-predicate or cross-session information leaks
- **Practical efficiency**: ~700 constraints (Groth16), verification in <Xms, constant-size proofs

---

## 2. System Components

### 2.1 Entities

| Entity | Role | Trust Assumption |
|--------|------|------------------|
| **Issuer (I)** | Issues credentials; knows all attribute values | Trusted (correct issuance) |
| **Holder (H)** | Stores credential; generates proofs | Honest (acts in own interest) |
| **Verifier A (V_A)** | Verifies specific predicate (e.g., Bank) | Honest-but-curious |
| **Verifier B (V_B)** | Verifies different predicate (e.g., Insurance) | Honest-but-curious |

### 2.2 Formal Definitions

**Attribute Vector**: x = (x₁, x₂, ..., xₙ) where xᵢ ∈ F_p (BN254 scalar field)

**Additive Shares**: For each attribute xᵢ, the Issuer computes:
- x̂ᵢ₁ ←$ F_p (uniform random)
- x̂ᵢ₂ = xᵢ − x̂ᵢ₁ (mod p)
- such that x̂ᵢ₁ + x̂ᵢ₂ = xᵢ (mod p)

**Poseidon Commitment**: For attribute xᵢ with blinding factor rᵢ ←$ F_p:
- Cᵢ = Poseidon(xᵢ, rᵢ)

**Credential**: cred = { (x̂ᵢ₁, x̂ᵢ₂, rᵢ, Cᵢ) for i = 1..n, σ }
where σ = HMAC_k(C₁ || C₂ || ... || Cₙ) is the issuer's signature.

---

## 3. Protocol Description

### 3.1 Issuance Protocol

```
Issuer I:
1. Receive attribute vector x = (age, income, ...) for holder H
2. For each attribute xᵢ:
   a. Sample x̂ᵢ₁ ←$ F_p
   b. Compute x̂ᵢ₂ = xᵢ − x̂ᵢ₁ (mod p)
   c. Sample rᵢ ←$ F_p
   d. Compute Cᵢ = Poseidon(xᵢ, rᵢ)
3. Sign: σ = HMAC_k(C₁ || ... || Cₙ)
4. Send cred = {shares, randomness, commitments, σ} to H
```

### 3.2 Proof Generation (Holder → Verifier)

```
Holder H proves "xⱼ > threshold" to Verifier V:
1. RE-RANDOMIZE (critical for unlinkability):
   a. Sample r' ←$ F_p (FRESH randomness)
   b. Compute C' = Poseidon(x̂ⱼ₁ + x̂ⱼ₂, r')
2. Generate Groth16 proof π with:
   - Private witness: (x̂ⱼ₁, x̂ⱼ₂, r')
   - Public inputs: (C', threshold)
   - Circuit enforces:
     * Poseidon(x̂ⱼ₁ + x̂ⱼ₂, r') = C'
     * (x̂ⱼ₁ + x̂ⱼ₂) > threshold
3. Send (π, C', threshold) to V
```

### 3.3 Verification

```
Verifier V:
1. Receive (π, C', threshold) from H
2. Run snarkjs.groth16.verify(vk, [C', threshold], π)
3. Output: ACCEPT or REJECT
4. Verifier learns ONLY the YES/NO decision
```

### 3.4 Protocol Flow Diagram

_[Member 4: Insert the draw.io / Excalidraw diagram here. See architecture_diagram.md for a Mermaid-based starting point.]_

---

## 4. Threat Model

### 4.1 Adversary Model

We consider an adversary **A** who:
- Controls up to k verifiers (V₁, ..., Vₖ)
- Each verifier is **honest-but-curious**: follows the protocol but attempts to extract additional information from proof transcripts
- Verifiers may **collude**: share transcripts (πᵢ, Cᵢ', thresholdᵢ) with each other
- The adversary cannot corrupt the Issuer

### 4.2 Security Goals

1. **Soundness**: A malicious holder cannot produce valid proofs for predicates that are false
2. **Zero-Knowledge**: Verifiers learn nothing beyond the predicate result (YES/NO)
3. **Unlinkability**: No PPT adversary can distinguish whether two proofs originate from the same holder with probability non-negligibly better than 1/2
4. **Collusion Resistance**: k colluding verifiers learn at most k independent bits (the k predicate results), and cannot compute any cross-predicate or identity-linking information

---

## 5. Security Claims

### Claim 1: Computational Unlinkability

**Statement**: Given transcripts T₁ = (π₁, C₁', threshold₁) and T₂ = (π₂, C₂', threshold₂), no PPT adversary A can compute a function f(T₁, T₂) → {same, different} with advantage ε over random guessing, under the Discrete Logarithm assumption on BN254.

**Argument**: Each transcript uses independently sampled randomness r₁', r₂' ←$ F_p. Because Poseidon is collision-resistant, C₁' ≠ C₂' with overwhelming probability even for the same attribute value. The Groth16 proofs π₁, π₂ are simulation-extractable and use independent randomness from the Fiat-Shamir transform. Therefore, (T₁, T₂) are jointly distributed identically to transcripts from two independent holders.

### Claim 2: Collusion Resistance

**Statement**: Given k transcripts {Tᵢ}ᵢ₌₁ᵏ from k colluding verifiers, adversary A learns exactly k bits {bᵢ ∈ {ACCEPT, REJECT}}ᵢ₌₁ᵏ and no additional algebraic structure linking the transcripts.

**Argument**: Each Tᵢ contains (πᵢ, Cᵢ', thresholdᵢ) where:
- Cᵢ' are Poseidon commitments with independent blinding factors
- πᵢ are Groth16 proofs with independent circuit-specific randomness
- thresholdᵢ are public plaintext values chosen by verifiers (not by holder)

No algebraic relation exists between (C₁', π₁) and (C₂', π₂) — they are cryptographically independent objects. Cross-transcript linkage requires either:
- Inverting Poseidon (contradicts collision resistance), or
- Extracting the witness from Groth16 proofs (contradicts knowledge soundness)

### Claim 3: Simulation Extractability

**Statement**: For each verifier Vᵢ, the transcript Tᵢ is simulatable without knowledge of the witness (x̂ⱼ₁, x̂ⱼ₂, r').

**Argument**: The Groth16 proof system satisfies simulation soundness (Groth 2016). Given the public inputs (Cᵢ', thresholdᵢ), a simulator S can produce a transcript indistinguishable from a real proof without knowing the witness, using the simulation trapdoor. This means each verifier's view is simulatable, confirming zero-knowledge.

---

## 6. Architecture

_[Member 4: Replace with the final architecture diagram from draw.io / Excalidraw]_

See `architecture_diagram.md` for a Mermaid-based starting point.

```
┌─────────┐     credential.json    ┌─────────┐
│  ISSUER  │ ──────────────────────▶│  HOLDER  │
│  (Rust)  │                        │          │
└─────────┘                        └────┬─────┘
                                        │
                              ┌─────────┴──────────┐
                   prove income>5L         prove age>18
                   (fresh r₁)              (fresh r₂)
                              │                    │
                    ┌─────────▼─────┐   ┌─────────▼──────┐
                    │   VERIFIER A  │   │   VERIFIER B   │
                    │   (Bank)      │   │   (Insurance)  │
                    │               │   │                │
                    │ Sees: π₁,C₁' │   │ Sees: π₂,C₂'  │
                    │ Learns: YES   │   │ Learns: YES    │
                    └───────┬───────┘   └───────┬────────┘
                            │                    │
                            └────────┬───────────┘
                                     │ collude
                                     ▼
                            ╔═══════════════════╗
                            ║  CANNOT LINK π₁   ║
                            ║  AND π₂ TO SAME   ║
                            ║  USER             ║
                            ╚═══════════════════╝
```

---

## 7. Comparison with BBS+

| Feature | BBS+ Signatures | CRCS (This System) |
|---------|-----------------|---------------------|
| Selective Disclosure | ✅ Yes | ✅ Yes (via predicate proofs) |
| Unlinkability | ✅ Via randomization | ✅ Via re-randomized Poseidon commitments |
| Collusion Resistance | ⚠️ Partial (linked pseudonyms possible) | ✅ Full (no algebraic linkage) |
| Predicate Proofs | ❌ Not native (needs ZK range proofs on top) | ✅ Native (built into circuit) |
| Proof System | Pairing-based | Groth16 (universal, post-quantum upgradable) |
| Proof Size | ~300 bytes (varies with disclosed attributes) | ~128 bytes (constant, Groth16) |
| Verifier Computation | Pairing checks (O(n) in attributes) | Single pairing check (O(1)) |
| Issuer Complexity | BLS signatures + rerandomization | Poseidon hash + HMAC (simpler) |
| ZK-Friendly Hash | ❌ Not needed | ✅ Poseidon (circom-native) |

**Key Advantage**: BBS+ allows a verifier to create a pseudonym from the credential, which can be correlated across verifiers. CRCS avoids this entirely by never exposing any persistent algebraic structure — each proof session is cryptographically independent.

---

## 8. Benchmarks

_[Member 4: Pull final numbers from Member 3's benchmark report and insert here]_

| Metric | Value |
|--------|-------|
| Circuit constraints | ~700 |
| Proof generation time | _[from benchmarks]_ ms |
| Verification time | _[from benchmarks]_ ms |
| Proof size | ~128 bytes (raw) / _[from benchmarks]_ bytes (JSON) |
| Trusted setup (one-time) | _[from benchmarks]_ seconds |

---

## 9. Future Work

1. **Threshold Issuance**: Replace single-issuer model with k-of-n threshold issuance using Shamir's Secret Sharing + distributed key generation (DKG). This eliminates the single point of trust in the issuer.

2. **Credential Revocation**: Implement sparse Merkle tree-based revocation. The holder proves non-membership in the revocation set inside the ZK circuit. Adds ~2000 constraints for a 32-level Merkle tree.

3. **Mobile Optimization**: Port the prover to WebAssembly for in-browser proof generation. Initial measurements suggest Groth16 proving on mobile is feasible within 2-3 seconds.

4. **Post-Quantum Upgrade Path**: Replace Groth16 with a STARK-based proof system (e.g., Plonky2) for post-quantum security. The circuit logic remains identical; only the proof system changes.

5. **Multi-Predicate Batching**: Allow a holder to prove multiple predicates in a single proof (e.g., "age > 18 AND income > 5L") to reduce proof count.

6. **Formal Verification**: Mechanize the security proofs in EasyCrypt or similar framework to provide machine-checked security guarantees.

---

## Appendix A: Notation Reference

| Symbol | Meaning |
|--------|---------|
| F_p | BN254 scalar field (prime p ≈ 2²⁵⁴) |
| xᵢ | i-th attribute value |
| x̂ᵢ₁, x̂ᵢ₂ | Additive shares of xᵢ |
| rᵢ | Blinding randomness for attribute i |
| Cᵢ | Poseidon commitment: Poseidon(xᵢ, rᵢ) |
| πᵢ | Groth16 proof for the i-th predicate |
| σ | Issuer's HMAC signature |
| vk | Groth16 verification key (public) |

---

## Appendix B: Circom Circuit Specification

See `src/circuits/full_predicate.circom` for the implementation.

**Signals**:
- Private: `x1`, `x2`, `r`
- Public: `commitment`, `threshold`

**Constraints**:
1. `x ← x1 + x2` (free — linear constraint)
2. `Poseidon(x, r) === commitment` (~240 constraints)
3. `x > threshold` (64-bit comparison, ~450 constraints)
