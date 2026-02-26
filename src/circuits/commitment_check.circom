/**
 * commitment_check.circom
 * 
 * CRCS Circuit 1: Commitment Verification
 * 
 * Proves knowledge of (x1, x2, r) such that:
 *   Poseidon(x1 + x2, r) == commitment  (public)
 * 
 * without revealing x1, x2, or r.
 * 
 * This is the foundational circuit — it proves that the holder knows
 * the opening of a Poseidon commitment without revealing the value.
 * 
 * Dependencies: circomlib (install via npm)
 *   npm install circomlib
 */

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * CommitmentCheck: Verify that Poseidon(x1 + x2, r) == expectedCommitment
 * 
 * Private inputs:
 *   - x1: first additive share of attribute
 *   - x2: second additive share of attribute
 *   - r:  blinding randomness
 * 
 * Public inputs:
 *   - expectedCommitment: the Poseidon commitment to verify against
 * 
 * Constraints: ~240 (Poseidon with 2 inputs)
 */
template CommitmentCheck() {
    // Private inputs (witness)
    signal input x1;
    signal input x2;
    signal input r;

    // Public input
    signal input expectedCommitment;

    // Step 1: Reconstruct the attribute value from shares
    signal x;
    x <== x1 + x2;

    // Step 2: Compute Poseidon commitment: C = Poseidon(x, r)
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== x;
    poseidon.inputs[1] <== r;

    // Step 3: Verify commitment matches
    expectedCommitment === poseidon.out;
}

component main {public [expectedCommitment]} = CommitmentCheck();
