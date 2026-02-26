/**
 * generate_input.js
 * 
 * Helper script to generate valid circom input JSON with correct Poseidon commitments.
 * This is essential because the commitment in input.json must match what the circuit computes.
 * 
 * Usage:
 *   node generate_input.js --x1 7 --x2 18 --r 12345678901234567890 --threshold 18
 *   node generate_input.js --value 25 --threshold 18    (auto-generates shares and randomness)
 * 
 * Output: Writes input.json with all signals correctly computed.
 * 
 * Prerequisites:
 *   npm install circomlibjs
 */

const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const crypto = require("crypto");

async function main() {
    const args = parseArgs(process.argv.slice(2));

    console.log("╔══════════════════════════════════════════╗");
    console.log("║   CRCS Input Generator                   ║");
    console.log("╚══════════════════════════════════════════╝");
    console.log();

    // Build Poseidon hash function (same parameters as circom's Poseidon)
    const poseidon = await buildPoseidon();

    let x1, x2, r;

    if (args.value !== undefined) {
        // Auto-generate shares and randomness
        const value = BigInt(args.value);
        const threshold = BigInt(args.threshold || "0");

        // Generate random x1 (256-bit)
        const x1Bytes = crypto.randomBytes(31); // Stay within BN254 field
        x1 = BigInt("0x" + x1Bytes.toString("hex"));

        // BN254 scalar field order
        const p = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        x2 = ((value - x1) % p + p) % p;

        r = BigInt("0x" + crypto.randomBytes(31).toString("hex"));

        console.log(`  Value: ${value}`);
        console.log(`  Threshold: ${threshold}`);
        console.log(`  x1 (random share): ${x1}`);
        console.log(`  x2 (derived share): ${x2}`);
        console.log(`  x1 + x2 mod p = ${(x1 + x2) % p}`);
        console.log(`  r (random blinding): ${r}`);
    } else {
        // Use provided values
        x1 = BigInt(args.x1 || "0");
        x2 = BigInt(args.x2 || "0");
        r = BigInt(args.r || "0");
    }

    const threshold = BigInt(args.threshold || "0");

    // Compute Poseidon commitment: C = Poseidon(x1 + x2, r)
    const p = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    const x = ((x1 + x2) % p + p) % p;

    // poseidon.F.toObject converts the internal representation to a BigInt
    const commitment = poseidon.F.toObject(poseidon([x, r]));

    console.log();
    console.log(`  Poseidon commitment: ${commitment}`);
    console.log();

    // Build the input JSON (circom expects decimal strings)
    const input = {
        x1: x1.toString(),
        x2: x2.toString(),
        r: r.toString(),
        commitment: commitment.toString(),
        threshold: threshold.toString()
    };

    // Write to input.json
    const outputFile = args.output || "input.json";
    fs.writeFileSync(outputFile, JSON.stringify(input, null, 4));
    console.log(`  ✅ Input written to: ${outputFile}`);
    console.log();

    // Verify x > threshold
    if (x > threshold) {
        console.log(`  ✅ Predicate check: ${x} > ${threshold} = TRUE`);
    } else {
        console.log(`  ⚠️  Predicate check: ${x} > ${threshold} = FALSE`);
        console.log(`     The proof will FAIL! Increase value or decrease threshold.`);
    }
}

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 2) {
        const key = argv[i].replace(/^--/, "");
        args[key] = argv[i + 1];
    }
    return args;
}

main().catch(console.error);
