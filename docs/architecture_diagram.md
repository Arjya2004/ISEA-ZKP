# CRCS Architecture Diagram (Mermaid)

Use this as a starting point. Export to a proper diagram tool like draw.io or Excalidraw for the final submission.

## Full System Flow

```mermaid
sequenceDiagram
    participant I as 🏛️ Issuer<br/>(Rust)
    participant H as 👤 Holder
    participant VA as 🏦 Bank<br/>(Verifier A)
    participant VB as 🏥 Insurance<br/>(Verifier B)

    Note over I,H: Phase 1: Credential Issuance
    I->>I: Generate shares: x̂₁, x̂₂ = x - x̂₁
    I->>I: Compute commitments: C = Poseidon(x, r)
    I->>I: Sign: σ = HMAC(C₁ || C₂ || ...)
    I->>H: Send credential {shares, commitments, σ}

    Note over H,VA: Phase 2: Prove income > 5L to Bank
    H->>H: Sample FRESH r₁' ←$ F_p
    H->>H: Compute C₁' = Poseidon(income, r₁')
    H->>H: Generate Groth16 proof π₁
    H->>VA: Send (π₁, C₁', threshold=500000)
    VA->>VA: snarkjs.groth16.verify(vk, [C₁', 500000], π₁)
    VA-->>H: ✅ VERIFIED (income > 5L)

    Note over H,VB: Phase 3: Prove age > 18 to Insurance
    H->>H: Sample DIFFERENT r₂' ←$ F_p
    H->>H: Compute C₂' = Poseidon(age, r₂')
    H->>H: Generate Groth16 proof π₂
    H->>VB: Send (π₂, C₂', threshold=18)
    VB->>VB: snarkjs.groth16.verify(vk, [C₂', 18], π₂)
    VB-->>H: ✅ VERIFIED (age > 18)

    Note over VA,VB: Phase 4: Collusion Attempt
    VA->>VB: Share transcript (π₁, C₁', 500000)
    VB->>VA: Share transcript (π₂, C₂', 18)
    Note over VA,VB: ❌ Cannot link:<br/>C₁' ≠ C₂' (different randomness)<br/>π₁ ≠ π₂ (independent proofs)<br/>No algebraic structure shared
```

## Component Architecture

```mermaid
graph TB
    subgraph "Issuer Module (Rust)"
        A[CLI: crcs-issuer] --> B[credential.rs]
        B --> C[poseidon.rs]
        B --> D[Additive Sharing]
        B --> E[HMAC Signing]
        B --> F[credential.json]
    end

    subgraph "Prover Layer (Circom + snarkjs)"
        G[full_predicate.circom] --> H[Poseidon Check]
        G --> I[Range Proof]
        J[setup.sh] --> K[Trusted Setup]
        L[prove.sh] --> M[Witness Gen]
        L --> N[Groth16 Prove]
    end

    subgraph "Verifier Module (Node.js)"
        O[verifier.js] --> P[snarkjs.verify]
        Q[collusion_demo.js] --> R[Transcript Comparison]
        S[benchmark.js] --> T[Performance Report]
    end

    F -->|input.json| L
    N -->|proof.json| O
    K -->|verification_key.json| O
```

## Credential Data Flow

```mermaid
graph LR
    subgraph "Attribute"
        X["x (e.g. age=25)"]
    end

    subgraph "Secret Sharing"
        X --> X1["x̂₁ (random)"]
        X --> X2["x̂₂ = x - x̂₁"]
    end

    subgraph "Commitment"
        X --> |"+ random r"| C["C = Poseidon(x, r)"]
    end

    subgraph "ZK Proof"
        X1 --> |"private witness"| PI["π (Groth16)"]
        X2 --> |"private witness"| PI
        C --> |"public input"| PI
    end

    subgraph "Verifier"
        PI --> |"verify"| V["YES / NO"]
        C --> |"public"| V
    end
```
