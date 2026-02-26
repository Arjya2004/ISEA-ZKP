///! CRCS Credential module.
///!
///! Core logic for credential generation:
///! - Additive secret sharing of attributes over BN254 scalar field
///! - Poseidon commitments for each attribute
///! - HMAC-SHA256 signing of the credential
///! - Re-randomization support (fresh randomness per proof session)

use ark_bn254::Fr;
use ark_ff::{PrimeField, UniformRand};
use core::str::FromStr;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::poseidon::{fr_to_decimal_string, poseidon_commit, u64_to_fr};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────

/// A single attribute with its additive shares and commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeCredential {
    /// Human-readable name (e.g. "age", "income")
    pub name: String,

    /// Share 1 of the attribute value (decimal string for circom compat)
    pub x1: String,

    /// Share 2 of the attribute value (decimal string for circom compat)
    pub x2: String,

    /// Blinding randomness used in the commitment (decimal string)
    pub randomness: String,

    /// Poseidon commitment C = Poseidon(x1 + x2, r) — (decimal string)
    pub commitment: String,
}

/// Full credential issued to a holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Protocol version
    pub version: String,

    /// Curve used (always BN254 for circom compatibility)
    pub curve: String,

    /// Hash function used for commitments
    pub hash: String,

    /// List of attribute credentials
    pub attributes: Vec<AttributeCredential>,

    /// HMAC-SHA256 signature over all commitments (hex)
    pub signature: String,
}

// ─────────────────────────────────────────────────────────────
// Core functions
// ─────────────────────────────────────────────────────────────

/// Generate additive shares for a value: x = x1 + x2 (mod p).
///
/// x1 is sampled uniformly at random from the field.
/// x2 = x - x1 (mod p).
///
/// This is the simplest form of 2-of-2 additive secret sharing.
/// The holder stores both shares; each share alone reveals nothing about x.
pub fn generate_shares(value: Fr) -> (Fr, Fr) {
    let mut rng = OsRng;
    let x1 = Fr::rand(&mut rng);
    let x2 = value - x1; // mod p automatically in ark-ff
    (x1, x2)
}

/// Generate a fresh random blinding factor for the Poseidon commitment.
pub fn generate_randomness() -> Fr {
    let mut rng = OsRng;
    Fr::rand(&mut rng)
}

/// Re-randomize a credential's commitment for a new proof session.
///
/// This is CRITICAL for unlinkability: each time the holder generates
/// a proof, they must use fresh randomness so that two proofs for the
/// same attribute cannot be linked by comparing commitments.
///
/// Returns (new_randomness, new_commitment).
pub fn rerandomize_commitment(value: Fr) -> (Fr, Fr) {
    let r_new = generate_randomness();
    let c_new = poseidon_commit(value, r_new);
    (r_new, c_new)
}

/// Build a credential from a list of (name, value) attribute pairs.
///
/// For each attribute:
/// 1. Convert value to field element
/// 2. Generate additive shares: x = x1 + x2
/// 3. Generate random blinding factor r
/// 4. Compute commitment C = Poseidon(x, r)
/// 5. Store all of {name, x1, x2, r, C} in the credential
///
/// Finally, HMAC-sign all commitments together.
pub fn build_credential(
    attributes: &[(String, u64)],
    signing_key: &[u8],
) -> Credential {
    let mut attr_creds = Vec::new();

    for (name, value) in attributes {
        let x = u64_to_fr(*value);
        let (x1, x2) = generate_shares(x);
        let r = generate_randomness();
        let c = poseidon_commit(x, r);

        attr_creds.push(AttributeCredential {
            name: name.clone(),
            x1: fr_to_decimal_string(&x1),
            x2: fr_to_decimal_string(&x2),
            randomness: fr_to_decimal_string(&r),
            commitment: fr_to_decimal_string(&c),
        });
    }

    // Sign all commitments concatenated
    let signature = sign_commitments(&attr_creds, signing_key);

    Credential {
        version: "0.1.0".to_string(),
        curve: "BN254".to_string(),
        hash: "Poseidon".to_string(),
        attributes: attr_creds,
        signature,
    }
}

/// HMAC-SHA256 sign the concatenation of all commitment strings.
///
/// In Phase I, HMAC is sufficient. For production, replace with
/// Schnorr or BLS signature over the commitments.
fn sign_commitments(attrs: &[AttributeCredential], key: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");

    for attr in attrs {
        mac.update(attr.commitment.as_bytes());
        mac.update(b"|"); // delimiter
    }

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify the HMAC signature on a credential.
pub fn verify_signature(credential: &Credential, key: &[u8]) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");

    for attr in &credential.attributes {
        mac.update(attr.commitment.as_bytes());
        mac.update(b"|");
    }

    let expected = hex::decode(&credential.signature).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}

// ─────────────────────────────────────────────────────────────
// Circom input generation
// ─────────────────────────────────────────────────────────────

/// Generate a circom-compatible input JSON for proving a predicate
/// on a specific attribute (e.g., "age > 18").
///
/// The JSON will contain:
/// - x1, x2: the additive shares
/// - r: the blinding randomness
/// - commitment: the public commitment (will be a public signal)
/// - threshold: the comparison threshold (will be a public signal)
///
/// Output is a JSON string ready to write to input.json for snarkjs.
#[derive(Debug, Serialize, Deserialize)]
pub struct CircomInput {
    pub x1: String,
    pub x2: String,
    pub r: String,
    pub commitment: String,
    pub threshold: String,
}

pub fn generate_circom_input(
    credential: &Credential,
    attribute_name: &str,
    threshold: u64,
) -> Result<CircomInput, String> {
    let attr = credential
        .attributes
        .iter()
        .find(|a| a.name == attribute_name)
        .ok_or_else(|| format!("Attribute '{}' not found in credential", attribute_name))?;

    Ok(CircomInput {
        x1: attr.x1.clone(),
        x2: attr.x2.clone(),
        r: attr.randomness.clone(),
        commitment: attr.commitment.clone(),
        threshold: threshold.to_string(),
    })
}

/// Generate a FRESH circom input with re-randomized commitment.
/// This MUST be used for each new proof session to ensure unlinkability.
///
/// The returned input uses:
/// - Same shares x1, x2 (the attribute value hasn't changed)
/// - NEW randomness r' (freshly sampled)
/// - NEW commitment C' = Poseidon(x1+x2, r')
pub fn generate_fresh_circom_input(
    credential: &Credential,
    attribute_name: &str,
    threshold: u64,
) -> Result<CircomInput, String> {
    let attr = credential
        .attributes
        .iter()
        .find(|a| a.name == attribute_name)
        .ok_or_else(|| format!("Attribute '{}' not found in credential", attribute_name))?;

    // Parse the shares back to field elements using Fr::from_str (decimal string)
    let x1 = Fr::from_str(&attr.x1).map_err(|_| "Failed to parse x1 as field element".to_string())?;
    let x2 = Fr::from_str(&attr.x2).map_err(|_| "Failed to parse x2 as field element".to_string())?;

    // Reconstruct value and re-randomize
    let value = x1 + x2;
    let (r_new, c_new) = rerandomize_commitment(value);

    Ok(CircomInput {
        x1: attr.x1.clone(),
        x2: attr.x2.clone(),
        r: fr_to_decimal_string(&r_new),
        commitment: fr_to_decimal_string(&c_new),
        threshold: threshold.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shares_reconstruct() {
        let value = u64_to_fr(42);
        let (x1, x2) = generate_shares(value);
        assert_eq!(x1 + x2, value, "Shares must reconstruct to original value");
    }

    #[test]
    fn test_shares_are_random() {
        let value = u64_to_fr(42);
        let (x1_a, _) = generate_shares(value);
        let (x1_b, _) = generate_shares(value);
        assert_ne!(x1_a, x1_b, "Shares should use fresh randomness each time");
    }

    #[test]
    fn test_build_credential() {
        let attrs = vec![
            ("age".to_string(), 22u64),
            ("income".to_string(), 600000u64),
        ];
        let key = b"test-signing-key-phase1";
        let cred = build_credential(&attrs, key);

        assert_eq!(cred.attributes.len(), 2);
        assert_eq!(cred.curve, "BN254");
        assert_eq!(cred.hash, "Poseidon");
        assert!(!cred.signature.is_empty());
    }

    #[test]
    fn test_signature_verification() {
        let attrs = vec![("age".to_string(), 25u64)];
        let key = b"test-key";
        let cred = build_credential(&attrs, key);

        assert!(verify_signature(&cred, key), "Valid signature should verify");
        assert!(
            !verify_signature(&cred, b"wrong-key"),
            "Wrong key should not verify"
        );
    }

    #[test]
    fn test_circom_input_generation() {
        let attrs = vec![("age".to_string(), 25u64)];
        let key = b"test-key";
        let cred = build_credential(&attrs, key);

        let input = generate_circom_input(&cred, "age", 18).unwrap();
        assert_eq!(input.threshold, "18");
        assert!(!input.x1.is_empty());
        assert!(!input.commitment.is_empty());
    }

    #[test]
    fn test_rerandomize_produces_different_commitments() {
        let value = u64_to_fr(25);
        let (_, c1) = rerandomize_commitment(value);
        let (_, c2) = rerandomize_commitment(value);
        assert_ne!(c1, c2, "Re-randomized commitments must differ");
    }
}
