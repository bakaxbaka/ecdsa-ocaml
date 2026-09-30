#!/bin/bash
#
# check-layering.sh — Verify ecdsa-ocaml respects layering constraints
#
# Enforces: application -> storage -> analysis -> bitcoin -> crypto -> common
#
# Usage: ./tools/check-layering.sh [--verbose]

VERBOSE=${1:-}

echo "=== ecdsa-ocaml Layering Check ==="
echo ""

# Layer hierarchy (higher number = higher/more dependent)
declare -A layer_order=(
    [common]=1
    [crypto]=2
    [bitcoin]=3
    [analysis]=4
    [storage]=5
    [application]=6
)

# Map library to layer
declare -A lib_to_layer=(
    [common]=common
    [field]=crypto
    [scalar]=crypto
    [curve]=crypto
    [ecdsa_der]=crypto
    [hash]=crypto
    [encoding]=crypto
    [bitcoin_tx]=bitcoin
    [script_types]=bitcoin
    [sighash]=bitcoin
    [bitcoin]=bitcoin
    [nonce]=analysis
    [observation]=analysis
    [statistics]=analysis
    [analysis_signature]=analysis
    [analysis]=analysis
)

get_library_layer() {
    local lib=$1
    if [[ -n "${lib_to_layer[$lib]}" ]]; then
        echo "${lib_to_layer[$lib]}"
    else
        echo "external"
    fi
}

violations=0

# Scan key dune files
for dune_file in \
    lib/common/dune \
    lib/crypto/field/dune \
    lib/crypto/scalar/dune \
    lib/crypto/curve/dune \
    lib/crypto/ecdsa/dune \
    lib/crypto/hash/dune \
    lib/crypto/encoding/dune \
    lib/bitcoin/transaction/dune \
    lib/bitcoin/script/dune \
    lib/bitcoin/sighash/dune \
    lib/bitcoin/dune \
    lib/analysis/signature/dune \
    lib/analysis/nonce/dune \
    lib/analysis/statistics/dune
do
    [[ ! -f "$dune_file" ]] && continue
    
    # Extract layer from path
    layer=$(echo "$dune_file" | sed -E 's|lib/([a-z_]+)/.*|\1|')
    [[ -z "$layer" ]] && continue
    
    [[ -n "$VERBOSE" ]] && echo "Checking $layer: $dune_file"
    
    # Extract libraries from dune file
    libs=$(grep -oP '\(libraries\s+\K[^)]+' "$dune_file" 2>/dev/null || true)
    
    for lib in $libs; do
        # Skip empty or invalid names
        [[ ! $lib =~ ^[a-z_][-a-z0-9_]*$ ]] && continue
        
        dep_layer=$(get_library_layer "$lib")
        
        # Skip external
        [[ "$dep_layer" == "external" ]] && continue
        
        # In-layer deps OK
        [[ "$dep_layer" == "$layer" ]] && continue
        
        # Cross-layer: dep layer must be lower
        current_order=${layer_order[$layer]:-0}
        dep_order=${layer_order[$dep_layer]:-0}
        
        if [[ $dep_order -gt $current_order ]]; then
            echo "ERROR in $dune_file"
            echo "  $layer depends on $lib (from $dep_layer)"
            echo "  Violation: cannot depend upward"
            ((violations++))
        fi
    done
done

echo ""
if [[ $violations -eq 0 ]]; then
    echo "=== LAYERING CHECK PASSED ==="
    echo "All dependencies respect layer constraints"
    exit 0
else
    echo "=== LAYERING VIOLATIONS: $violations ==="
    exit 1
fi
