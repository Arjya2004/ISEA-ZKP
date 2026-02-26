#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# CRCS — End-to-End Demo Script
# ═══════════════════════════════════════════════════════════════
#
# This script runs the complete CRCS flow:
#   1. Issue a credential (Rust issuer)
#   2. Generate proof for Bank (income > 5L)
#   3. Generate proof for Insurance (age > 18)
#   4. Verify both proofs
#   5. Run collusion resistance demo
#
# Prerequisites:
#   - Rust toolchain (for issuer)
#   - Node.js + npm
#   - circom + snarkjs
#   - All setup steps completed (see README.md)
#
# Usage:
#   chmod +x demo.sh
#   ./demo.sh
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISSUER_DIR="$SCRIPT_DIR/src/issuer"
CIRCUITS_DIR="$SCRIPT_DIR/src/circuits"
VERIFIER_DIR="$SCRIPT_DIR/src/verifier"
BUILD_DIR="$CIRCUITS_DIR/build"
OUTPUT_DIR="$SCRIPT_DIR/demo_output"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║   CRCS — Collusion-Resistant Credential System           ║"
echo "║   End-to-End Demonstration                               ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

mkdir -p "$OUTPUT_DIR"

# ─── Phase 1: Credential Issuance ─────────────────────────
echo "═══════════════════════════════════════════════"
echo "  PHASE 1: Credential Issuance"
echo "═══════════════════════════════════════════════"
echo ""

cd "$ISSUER_DIR"

# Build the issuer if not already built
if [ ! -f "target/release/crcs-issuer" ]; then
    echo "  🔨 Building Rust issuer..."
    cargo build --release 2>&1 | tail -1
fi

echo "  📋 Issuing credential for user with age=25, income=600000, smoker=0..."
./target/release/crcs-issuer issue \
    --attributes "age=25,income=600000,smoker=0" \
    --output "$OUTPUT_DIR/credential.json"

echo ""

# ─── Phase 2: Generate Proof for Bank ─────────────────────
echo "═══════════════════════════════════════════════"
echo "  PHASE 2: Prove income > 500000 to Bank"
echo "═══════════════════════════════════════════════"
echo ""

echo "  📋 Generating circom input (fresh randomness)..."
./target/release/crcs-issuer prove \
    --credential "$OUTPUT_DIR/credential.json" \
    --attribute income \
    --threshold 500000 \
    --output "$OUTPUT_DIR/bank_input.json" \
    --fresh

cd "$CIRCUITS_DIR"

echo ""
echo "  🔐 Generating Groth16 proof for Bank..."
node "$BUILD_DIR/full_predicate_js/generate_witness.js" \
    "$BUILD_DIR/full_predicate_js/full_predicate.wasm" \
    "$OUTPUT_DIR/bank_input.json" \
    "$OUTPUT_DIR/bank_witness.wtns"

snarkjs groth16 prove \
    "$BUILD_DIR/full_predicate_final.zkey" \
    "$OUTPUT_DIR/bank_witness.wtns" \
    "$OUTPUT_DIR/bank_proof.json" \
    "$OUTPUT_DIR/bank_public.json"

echo "  ✅ Bank proof generated!"
echo ""

# ─── Phase 3: Generate Proof for Insurance ────────────────
echo "═══════════════════════════════════════════════"
echo "  PHASE 3: Prove age > 18 to Insurance"
echo "═══════════════════════════════════════════════"
echo ""

cd "$ISSUER_DIR"

echo "  📋 Generating circom input (DIFFERENT fresh randomness)..."
./target/release/crcs-issuer prove \
    --credential "$OUTPUT_DIR/credential.json" \
    --attribute age \
    --threshold 18 \
    --output "$OUTPUT_DIR/insurance_input.json" \
    --fresh

cd "$CIRCUITS_DIR"

echo ""
echo "  🔐 Generating Groth16 proof for Insurance..."
node "$BUILD_DIR/full_predicate_js/generate_witness.js" \
    "$BUILD_DIR/full_predicate_js/full_predicate.wasm" \
    "$OUTPUT_DIR/insurance_input.json" \
    "$OUTPUT_DIR/insurance_witness.wtns"

snarkjs groth16 prove \
    "$BUILD_DIR/full_predicate_final.zkey" \
    "$OUTPUT_DIR/insurance_witness.wtns" \
    "$OUTPUT_DIR/insurance_proof.json" \
    "$OUTPUT_DIR/insurance_public.json"

echo "  ✅ Insurance proof generated!"
echo ""

# ─── Phase 4: Verification ───────────────────────────────
echo "═══════════════════════════════════════════════"
echo "  PHASE 4: Verification"
echo "═══════════════════════════════════════════════"
echo ""

cd "$VERIFIER_DIR"

echo "  🏦 Bank verifies income proof..."
node verifier.js \
    --proof "$OUTPUT_DIR/bank_proof.json" \
    --public "$OUTPUT_DIR/bank_public.json" \
    --vkey "$BUILD_DIR/verification_key.json" \
    --name "Bank"

echo "  🏥 Insurance verifies age proof..."
node verifier.js \
    --proof "$OUTPUT_DIR/insurance_proof.json" \
    --public "$OUTPUT_DIR/insurance_public.json" \
    --vkey "$BUILD_DIR/verification_key.json" \
    --name "Insurance"
echo ""

# ─── Phase 5: Collusion Demo ─────────────────────────────
echo "═══════════════════════════════════════════════"
echo "  PHASE 5: Collusion Resistance Check"
echo "═══════════════════════════════════════════════"
echo ""

node collusion_demo.js --build-dir "$BUILD_DIR"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ DEMO COMPLETE"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Output files: $OUTPUT_DIR/"
echo "  Benchmarks:   $SCRIPT_DIR/benchmarks/"
echo ""
