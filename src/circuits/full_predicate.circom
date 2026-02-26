/**
 * full_predicate.circom
 * 
 * CRCS Circuit 3: Combined Predicate Proof
 * 
 * This is the MAIN circuit used in the demo. It combines:
 *   1. Commitment verification: Poseidon(x1 + x2, r) == commitment
 *   2. Range proof: (x1 + x2) > threshold
 * 
 * In one single Groth16 proof, we prove that:
 *   - The holder knows the opening of the commitment (knowledge of x1, x2, r)
 *   - The committed attribute value exceeds the threshold
 *   - Without revealing x1, x2, r, or the actual value x
 * 
 * Public signals: commitment, threshold
 * Private signals: x1, x2, r
 * 
 * This is what makes CRCS powerful — the verifier only learns YES/NO
 * and has no way to extract the actual attribute value.
 * 
 * Dependencies: circomlib
 */

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * FullPredicateProof: Combined commitment check + range proof.
 * 
 * @param n - Bit width for range comparison (default 64)
 * 
 * Private inputs:
 *   - x1: first additive share
 *   - x2: second additive share
 *   - r:  blinding randomness for the commitment
 * 
 * Public inputs:
 *   - commitment: Poseidon(x1+x2, r)
 *   - threshold:  the value to compare against
 * 
 * Constraints: ~700 total (Poseidon ~240 + comparison ~450 + misc)
 */
template FullPredicateProof(n) {
    // ─── Private inputs (witness) ───────────────────────────
    signal input x1;
    signal input x2;
    signal input r;

    // ─── Public inputs ──────────────────────────────────────
    signal input commitment;
    signal input threshold;

    // ─── Step 1: Reconstruct attribute value from shares ────
    signal x;
    x <== x1 + x2;

    // ─── Step 2: Verify Poseidon commitment ─────────────────
    // Proves: holder knows (x, r) such that Poseidon(x, r) == commitment
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== x;
    poseidon.inputs[1] <== r;

    // Constrain: computed commitment must equal public commitment
    commitment === poseidon.out;

    // ─── Step 3: Range check ────────────────────────────────
    // Proves: x > threshold without revealing x
    component gt = GreaterThan(n);
    gt.in[0] <== x;
    gt.in[1] <== threshold;

    // Constrain: the comparison must pass (x > threshold)
    gt.out === 1;
}

/**
 * Main component with 64-bit range check.
 * 
 * Public signals: commitment, threshold
 * 
 * Example usage with snarkjs:
 *   Public signals in order: [commitment, threshold]
 *   Private witness:         [x1, x2, r]
 */
component main {public [commitment, threshold]} = FullPredicateProof(64);
