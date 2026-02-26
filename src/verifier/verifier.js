/**
 * verifier.js
 * 
 * CRCS Verifier — Wraps snarkjs Groth16 verification.
 * 
 * Each verifier (Bank, Insurance, etc.) runs this to check a proof.
 * The verifier only learns YES/NO — nothing about the actual attribute value.
 * 
 * Usage:
 *   node verifier.js --proof proof.json --public public.json --vkey verification_key.json
 *   node verifier.js --proof proof.json --public public.json --vkey verification_key.json --name "Bank"
 * 
 * Can also be imported as a module:
 *   const { verifyProof } = require('./verifier');
 */

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

// ─────────────────────────────────────────────────────────────
// Core verification function
// ─────────────────────────────────────────────────────────────

/**
 * Verify a Groth16 proof against public signals and verification key.
 * 
 * @param {Object} proof - The Groth16 proof (π)
 * @param {Array}  publicSignals - Public inputs [commitment, threshold]
 * @param {Object} vkey - Verification key from trusted setup
 * @returns {boolean} true if proof is valid
 */
async function verifyProof(proof, publicSignals, vkey) {
    try {
        const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
        return isValid;
    } catch (err) {
        console.error("Verification error:", err.message);
        return false;
    }
}

/**
 * Load JSON from file path.
 */
function loadJSON(filePath) {
    const raw = fs.readFileSync(path.resolve(filePath), "utf-8");
    return JSON.parse(raw);
}

/**
 * Run verification as a specific verifier entity (e.g., "Bank", "Insurance").
 * Prints a formatted result with the verifier's name.
 */
async function runVerification(proofPath, publicPath, vkeyPath, verifierName) {
    const proof = loadJSON(proofPath);
    const publicSignals = loadJSON(publicPath);
    const vkey = loadJSON(vkeyPath);

    const name = verifierName || "Verifier";

    console.log(`╔══════════════════════════════════════════╗`);
    console.log(`║   CRCS Verification — ${name.padEnd(18)}   ║`);
    console.log(`╚══════════════════════════════════════════╝`);
    console.log();

    console.log(`  📋 Public signals:`);
    publicSignals.forEach((sig, i) => {
        console.log(`     [${i}]: ${sig}`);
    });
    console.log();

    // Time the verification
    const startTime = process.hrtime.bigint();
    const isValid = await verifyProof(proof, publicSignals, vkey);
    const endTime = process.hrtime.bigint();
    const durationMs = Number(endTime - startTime) / 1_000_000;

    if (isValid) {
        console.log(`  ✅ RESULT: VERIFIED — Attribute satisfies the predicate.`);
    } else {
        console.log(`  ❌ RESULT: REJECTED — Proof is invalid.`);
    }
    console.log(`  ⏱️  Verification time: ${durationMs.toFixed(2)}ms`);
    console.log();

    return {
        verifier: name,
        valid: isValid,
        publicSignals,
        verificationTimeMs: durationMs,
        proofPath,
    };
}

// ─────────────────────────────────────────────────────────────
// CLI mode
// ─────────────────────────────────────────────────────────────

if (require.main === module) {
    const args = parseArgs(process.argv.slice(2));

    if (!args.proof || !args.public || !args.vkey) {
        console.log("Usage: node verifier.js --proof <proof.json> --public <public.json> --vkey <vkey.json> [--name <VerifierName>]");
        process.exit(1);
    }

    runVerification(args.proof, args.public, args.vkey, args.name)
        .then((result) => {
            process.exit(result.valid ? 0 : 1);
        })
        .catch((err) => {
            console.error("Fatal error:", err);
            process.exit(2);
        });
}

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 2) {
        const key = argv[i].replace(/^--/, "");
        args[key] = argv[i + 1];
    }
    return args;
}

module.exports = { verifyProof, runVerification, loadJSON };
