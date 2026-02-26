///! Poseidon hash wrapper for CRCS.
///!
///! This module wraps the `light-poseidon` crate to compute Poseidon hashes
///! compatible with circom's Poseidon implementation (BN254 scalar field).
///!
///! The Poseidon hash is ZK-friendly — far more efficient inside a circom circuit
///! than SHA256 or Keccak. This is a key engineering decision for the project.

use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};

/// Compute Poseidon hash of two field elements: H(a, b).
/// This matches circom's `Poseidon(2)` template from circomlib.
///
/// # Arguments
/// * `a` - First input field element
/// * `b` - Second input field element
///
/// # Returns
/// The Poseidon hash as a BN254 scalar field element.
pub fn poseidon_hash_two(a: Fr, b: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("Failed to init Poseidon(2)");
    poseidon.hash(&[a, b]).expect("Poseidon hash failed")
}

/// Compute the Poseidon commitment: C = Poseidon(x, r)
/// where x is the attribute value and r is the blinding randomness.
///
/// This is used instead of a full Pedersen commitment because:
/// 1. It's much cheaper inside a circom Groth16 circuit (~200 constraints vs ~2000+)
/// 2. It's binding under the same assumptions (collision resistance of Poseidon)
/// 3. It's hiding when r is uniformly random
///
/// # Arguments
/// * `value` - The attribute value (reconstructed: x = x1 + x2)
/// * `randomness` - Blinding factor r
///
/// # Returns
/// The commitment C as a field element.
pub fn poseidon_commit(value: Fr, randomness: Fr) -> Fr {
    poseidon_hash_two(value, randomness)
}

/// Convert a u64 to a BN254 field element.
/// Useful for converting attribute values (age, income, etc.) to field elements.
pub fn u64_to_fr(val: u64) -> Fr {
    Fr::from(val)
}

/// Convert a field element to its decimal string representation.
/// Needed for generating circom-compatible input JSON (circom uses decimal strings).
pub fn fr_to_decimal_string(f: &Fr) -> String {
    let bigint: BigInteger256 = f.into_bigint();
    // Convert to decimal string
    let bytes = bigint.0;
    // Use the BigInteger's to_string which gives decimal
    format_bigint_decimal(&bytes)
}

/// Format a 4×u64 limb representation as a decimal string.
fn format_bigint_decimal(limbs: &[u64; 4]) -> String {
    // For simplicity, if the value fits in u128, use that
    if limbs[2] == 0 && limbs[3] == 0 {
        let val = limbs[0] as u128 | ((limbs[1] as u128) << 64);
        return val.to_string();
    }
    // For larger values, use the ark-ff Display trait
    // This is a fallback — in practice, our attribute values fit in u64
    let fr = Fr::from_bigint(BigInteger256::new(*limbs)).unwrap();
    format!("{}", fr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_poseidon_deterministic() {
        let a = u64_to_fr(42);
        let b = u64_to_fr(123);
        let h1 = poseidon_hash_two(a, b);
        let h2 = poseidon_hash_two(a, b);
        assert_eq!(h1, h2, "Poseidon should be deterministic");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = u64_to_fr(42);
        let b = u64_to_fr(123);
        let c = u64_to_fr(999);
        let h1 = poseidon_hash_two(a, b);
        let h2 = poseidon_hash_two(a, c);
        assert_ne!(h1, h2, "Different inputs should give different hashes");
    }

    #[test]
    fn test_commitment_hiding() {
        let value = u64_to_fr(25);
        let r1 = u64_to_fr(111);
        let r2 = u64_to_fr(222);
        let c1 = poseidon_commit(value, r1);
        let c2 = poseidon_commit(value, r2);
        assert_ne!(c1, c2, "Same value with different randomness must give different commitments");
    }

    #[test]
    fn test_u64_to_fr_roundtrip() {
        let val = 600000u64;
        let fr = u64_to_fr(val);
        let s = fr_to_decimal_string(&fr);
        assert_eq!(s, "600000");
    }
}
