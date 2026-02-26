#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# CRCS Proof Generation Script
# ═══════════════════════════════════════════════════════════════
#
# Generates a Groth16 proof given an input JSON file.
# Must run setup.sh first to generate the circuit artifacts.
#
# Usage:
#   ./prove.sh <input.json> [circuit_name]
#
# Example:
#   ./prove.sh input.json full_predicate
#
# Output:
#   build/proof.json        — the ZK proof
#   build/public.json       — public signals (commitment, threshold)
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

INPUT_FILE="${1:?Usage: ./prove.sh <input.json> [circuit_name]}"
CIRCUIT="${2:-full_predicate}"
BUILD_DIR="./build"

echo "╔══════════════════════════════════════════╗"
echo "║       CRCS Proof Generation              ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Circuit: ${CIRCUIT}"
echo "Input:   ${INPUT_FILE}"
echo ""

# Check prerequisites
if [ ! -f "$BUILD_DIR/${CIRCUIT}_final.zkey" ]; then
    echo "❌ Error: Final zkey not found. Run setup.sh first!"
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "❌ Error: Input file '${INPUT_FILE}' not found."
    exit 1
fi

# ─── Step 1: Generate the witness ──────────────────────────
echo "🧮 [1/3] Generating witness..."

# snarkjs needs the WASM-based witness generator
node "$BUILD_DIR/${CIRCUIT}_js/generate_witness.js" \
    "$BUILD_DIR/${CIRCUIT}_js/${CIRCUIT}.wasm" \
    "$INPUT_FILE" \
    "$BUILD_DIR/witness.wtns"

echo "   ✅ Witness generated: $BUILD_DIR/witness.wtns"
echo ""

# ─── Step 2: Generate the proof ───────────────────────────
echo "🔐 [2/3] Generating Groth16 proof..."

# Time the proof generation (for benchmarks)
START_TIME=$(date +%s%N)

snarkjs groth16 prove \
    "$BUILD_DIR/${CIRCUIT}_final.zkey" \
    "$BUILD_DIR/witness.wtns" \
    "$BUILD_DIR/proof.json" \
    "$BUILD_DIR/public.json"

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "   ✅ Proof generated: $BUILD_DIR/proof.json"
echo "   ✅ Public signals:  $BUILD_DIR/public.json"
echo "   ⏱️  Proof time: ${DURATION_MS}ms"
echo ""

# ─── Step 3: Verify the proof locally ─────────────────────
echo "✔️  [3/3] Verifying proof locally..."

snarkjs groth16 verify \
    "$BUILD_DIR/verification_key.json" \
    "$BUILD_DIR/public.json" \
    "$BUILD_DIR/proof.json"

echo ""

# Print proof size
PROOF_SIZE=$(wc -c < "$BUILD_DIR/proof.json")
PUBLIC_SIZE=$(wc -c < "$BUILD_DIR/public.json")
echo "═══════════════════════════════════════════════════"
echo "  📊 Proof size:   ${PROOF_SIZE} bytes"
echo "  📊 Public size:  ${PUBLIC_SIZE} bytes"
echo "  ⏱️  Prove time:   ${DURATION_MS}ms"
echo ""
echo "  Files ready for verifier:"
echo "    $BUILD_DIR/proof.json"
echo "    $BUILD_DIR/public.json"
echo "    $BUILD_DIR/verification_key.json"
echo "═══════════════════════════════════════════════════"
