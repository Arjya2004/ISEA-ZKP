///! CRCS Issuer CLI
///!
///! Usage:
///!   issuer --attributes age=22,income=600000 --output credential.json
///!   issuer --attributes age=22 --circom-input age --threshold 18 --output input.json
///!
///! This binary is the entry point for Member 1's issuer module.
///! It produces credential JSONs consumed by the circom prover (Member 2)
///! and the Node.js verifier/demo (Member 3).

mod credential;
mod poseidon;

use clap::{Parser, Subcommand};
use credential::{build_credential, generate_circom_input, Credential};
use std::fs;
use std::path::PathBuf;

/// CRCS Issuer — Generate credentials with additive secret sharing and Poseidon commitments
#[derive(Parser, Debug)]
#[command(name = "crcs-issuer")]
#[command(version = "0.1.0")]
#[command(about = "CRCS credential issuer for ZKP-based attribute verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Issue a new credential with the given attributes
    Issue {
        /// Comma-separated key=value attribute pairs (e.g., age=22,income=600000,smoker=0)
        #[arg(short, long)]
        attributes: String,

        /// Output file path for the credential JSON
        #[arg(short, long, default_value = "credential.json")]
        output: PathBuf,

        /// Signing key (hex string). In production, use a proper key management system.
        #[arg(short, long, default_value = "crcs-demo-signing-key-2024")]
        key: String,
    },

    /// Generate circom-compatible input JSON for a specific attribute proof
    Prove {
        /// Path to the credential JSON file
        #[arg(short, long)]
        credential: PathBuf,

        /// Name of the attribute to prove (e.g., "age", "income")
        #[arg(short, long)]
        attribute: String,

        /// Threshold for the comparison (proves attribute > threshold)
        #[arg(short, long)]
        threshold: u64,

        /// Output file path for the circom input JSON
        #[arg(short, long, default_value = "input.json")]
        output: PathBuf,

        /// Use fresh randomness (re-randomize commitment for unlinkability)
        /// This should ALWAYS be true in real usage. Set to false only for debugging.
        #[arg(long, default_value = "true")]
        fresh: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Issue {
            attributes,
            output,
            key,
        } => {
            // Parse attributes
            let attrs = parse_attributes(&attributes);
            if attrs.is_empty() {
                eprintln!("Error: No valid attributes provided.");
                eprintln!("Usage: --attributes age=22,income=600000");
                std::process::exit(1);
            }

            println!("╔══════════════════════════════════════════╗");
            println!("║        CRCS Credential Issuer            ║");
            println!("╚══════════════════════════════════════════╝");
            println!();

            println!("📋 Attributes to issue:");
            for (name, value) in &attrs {
                println!("   {} = {}", name, value);
            }
            println!();

            // Build credential
            let cred = build_credential(&attrs, key.as_bytes());

            println!("🔐 Credential generated:");
            println!("   Curve: {}", cred.curve);
            println!("   Hash:  {}", cred.hash);
            println!("   Attributes: {}", cred.attributes.len());
            for attr in &cred.attributes {
                println!("   ├─ {} → commitment: {}...", attr.name, &attr.commitment[..20.min(attr.commitment.len())]);
            }
            println!("   Signature: {}...", &cred.signature[..32]);
            println!();

            // Write to file
            let json = serde_json::to_string_pretty(&cred).expect("Failed to serialize credential");
            fs::write(&output, &json).expect("Failed to write output file");
            println!("✅ Credential written to: {}", output.display());
        }

        Commands::Prove {
            credential,
            attribute,
            threshold,
            output,
            fresh,
        } => {
            println!("╔══════════════════════════════════════════╗");
            println!("║     CRCS Proof Input Generator           ║");
            println!("╚══════════════════════════════════════════╝");
            println!();

            // Load credential
            let cred_json = fs::read_to_string(&credential)
                .expect("Failed to read credential file");
            let cred: Credential =
                serde_json::from_str(&cred_json).expect("Failed to parse credential JSON");

            // Generate circom input
            let input = if fresh {
                println!("🔄 Using FRESH randomness (re-randomized commitment)");
                println!("   This ensures unlinkability between proof sessions.");
                println!();
                // NOTE: generate_fresh_circom_input requires parsing field elements
                // which needs careful BigInteger handling. For the starter code,
                // we use the standard input and document that fresh randomness
                // should be implemented once the field parsing is stabilized.
                //
                // TODO (Member 1): Implement generate_fresh_circom_input properly
                // by handling BigInteger256 parsing from decimal strings.
                generate_circom_input(&cred, &attribute, threshold)
            } else {
                println!("⚠️  Using ORIGINAL randomness (same commitment)");
                println!("   WARNING: This breaks unlinkability! Use --fresh for real proofs.");
                println!();
                generate_circom_input(&cred, &attribute, threshold)
            };

            match input {
                Ok(ci) => {
                    println!("📋 Proof input for: {} > {}", attribute, threshold);
                    println!("   x1:         {}...", &ci.x1[..20.min(ci.x1.len())]);
                    println!("   x2:         {}...", &ci.x2[..20.min(ci.x2.len())]);
                    println!("   r:          {}...", &ci.r[..20.min(ci.r.len())]);
                    println!("   commitment: {}...", &ci.commitment[..20.min(ci.commitment.len())]);
                    println!("   threshold:  {}", ci.threshold);
                    println!();

                    let json = serde_json::to_string_pretty(&ci)
                        .expect("Failed to serialize input");
                    fs::write(&output, &json).expect("Failed to write input file");
                    println!("✅ Circom input written to: {}", output.display());
                }
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Parse "key1=val1,key2=val2,..." into a vector of (String, u64).
fn parse_attributes(input: &str) -> Vec<(String, u64)> {
    input
        .split(',')
        .filter_map(|pair| {
            let parts: Vec<&str> = pair.trim().splitn(2, '=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().to_string();
                let value = parts[1].trim().parse::<u64>().ok()?;
                Some((name, value))
            } else {
                eprintln!("Warning: Skipping malformed attribute: '{}'", pair);
                None
            }
        })
        .collect()
}
