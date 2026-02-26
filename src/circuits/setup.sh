#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# CRCS Circuit Setup Script
# ═══════════════════════════════════════════════════════════════
#
# This script compiles the circom circuit and performs the
# Groth16 trusted setup (Powers of Tau ceremony + phase 2).
#
# Prerequisites:
#   - circom installed: https://docs.circom.io/getting-started/installation/
#   - snarkjs installed: npm install -g snarkjs
#   - circomlib installed in parent dir: (cd .. && npm install circomlib)
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh [circuit_name]
#
# Default circuit: full_predicate
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

CIRCUIT="${1:-full_predicate}"
BUILD_DIR="./build"
PTAU_FILE="$BUILD_DIR/pot14_final.ptau"

echo "╔══════════════════════════════════════════╗"
echo "║       CRCS Circuit Setup                 ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Circuit: ${CIRCUIT}.circom"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# ─── Step 1: Compile the circuit ───────────────────────────
echo "🔨 [1/6] Compiling circom circuit..."
circom "${CIRCUIT}.circom" \
    --r1cs \
    --wasm \
    --sym \
    --output "$BUILD_DIR" \
    -l ../node_modules

echo "   ✅ R1CS:  $BUILD_DIR/${CIRCUIT}.r1cs"
echo "   ✅ WASM:  $BUILD_DIR/${CIRCUIT}_js/"
echo "   ✅ SYM:   $BUILD_DIR/${CIRCUIT}.sym"
echo ""

# Print circuit info
echo "📊 Circuit statistics:"
snarkjs r1cs info "$BUILD_DIR/${CIRCUIT}.r1cs"
echo ""

# ─── Step 2: Powers of Tau ceremony (Phase 1) ─────────────
# We use 2^14 = 16384 constraints max. Adjust if circuit is larger.
if [ ! -f "$PTAU_FILE" ]; then
    echo "🔑 [2/6] Starting Powers of Tau ceremony..."
    
    snarkjs powersoftau new bn128 14 "$BUILD_DIR/pot14_0000.ptau" -v
    echo "   Phase 1 initialized."
    
    # Contribute randomness (in production, multiple parties do this)
    snarkjs powersoftau contribute \
        "$BUILD_DIR/pot14_0000.ptau" \
        "$BUILD_DIR/pot14_0001.ptau" \
        --name="CRCS Phase 1 contribution" \
        -e="random-entropy-for-hackathon-demo-$(date +%s)"
    echo "   Contribution added."
    
    # Prepare Phase 2
    snarkjs powersoftau prepare phase2 \
        "$BUILD_DIR/pot14_0001.ptau" \
        "$PTAU_FILE" \
        -v
    echo "   ✅ Powers of Tau ceremony complete."
else
    echo "⏭️  [2/6] Powers of Tau file already exists, skipping."
fi
echo ""

# ─── Step 3: Groth16 Setup (Phase 2) ──────────────────────
echo "🔧 [3/6] Running Groth16 setup..."
snarkjs groth16 setup \
    "$BUILD_DIR/${CIRCUIT}.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/${CIRCUIT}_0000.zkey"
echo "   Initial zkey created."

# ─── Step 4: Contribute to Phase 2 ────────────────────────
echo "🔑 [4/6] Contributing to Phase 2..."
snarkjs zkey contribute \
    "$BUILD_DIR/${CIRCUIT}_0000.zkey" \
    "$BUILD_DIR/${CIRCUIT}_final.zkey" \
    --name="CRCS Phase 2 contribution" \
    -e="more-random-entropy-$(date +%s)"
echo "   ✅ Final zkey generated."
echo ""

# ─── Step 5: Export verification key ──────────────────────
echo "📤 [5/6] Exporting verification key..."
snarkjs zkey export verificationkey \
    "$BUILD_DIR/${CIRCUIT}_final.zkey" \
    "$BUILD_DIR/verification_key.json"
echo "   ✅ Verification key: $BUILD_DIR/verification_key.json"
echo ""

# ─── Step 6: Verify the setup ─────────────────────────────
echo "✔️  [6/6] Verifying the setup..."
snarkjs zkey verify \
    "$BUILD_DIR/${CIRCUIT}.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/${CIRCUIT}_final.zkey"
echo ""

echo "═══════════════════════════════════════════════════"
echo "  ✅ Setup complete! Files in $BUILD_DIR/"
echo ""
echo "  Next step: ./prove.sh <input.json>"
echo "═══════════════════════════════════════════════════"
