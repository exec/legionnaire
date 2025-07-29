#!/bin/bash

# CI Fuzzing Script for IronChat
# Designed for automated testing in CI/CD pipelines

set -euo pipefail

# Configuration for CI environment
CI_DURATION=${CI_FUZZ_DURATION:-30}  # Shorter duration for CI
FAIL_ON_CRASH=${FAIL_ON_CRASH:-true}
ARTIFACT_DIR="ci_fuzz_artifacts"

echo "=== IronChat CI Fuzzing ==="
echo "Duration: ${CI_DURATION}s per target"
echo "Fail on crash: $FAIL_ON_CRASH"
echo

# Ensure we have cargo-fuzz
if ! command -v cargo-fuzz &> /dev/null; then
    echo "Installing cargo-fuzz..."
    cargo install cargo-fuzz
fi

# Clean previous artifacts
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

# Targets to test in CI
CI_TARGETS=(
    "fuzz_irc_message_parsing"
    "fuzz_tag_parsing"
    "fuzz_command_validation"
)

overall_success=true

for target in "${CI_TARGETS[@]}"; do
    echo "--- Testing $target ---"
    
    # Create minimal corpus
    mkdir -p "fuzz_corpus/$target"
    echo "PRIVMSG #test :hello" > "fuzz_corpus/$target/basic.txt"
    
    cd fuzz
    
    # Run fuzzer with timeout
    artifact_prefix="../$ARTIFACT_DIR/$target-"
    
    if timeout "${CI_DURATION}s" cargo fuzz run "$target" -- \
        -artifact_prefix="$artifact_prefix" \
        -print_final_stats=1 \
        -rss_limit_mb=1024 \
        2>&1 | tee "../$ARTIFACT_DIR/$target.log"; then
        echo "✓ $target completed successfully"
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "✓ $target completed (timeout)"
        else
            echo "✗ $target failed with exit code $exit_code"
            overall_success=false
        fi
    fi
    
    cd ..
    
    # Check for crashes
    crashes=$(find "$ARTIFACT_DIR" -name "$target-crash-*" 2>/dev/null | wc -l)
    if [ "$crashes" -gt 0 ]; then
        echo "⚠ Found $crashes crash(es) in $target"
        find "$ARTIFACT_DIR" -name "$target-crash-*" -exec echo "  - {}" \;
        
        if [ "$FAIL_ON_CRASH" = "true" ]; then
            overall_success=false
        fi
    fi
    
    echo
done

echo "=== CI Fuzzing Summary ==="
if [ "$overall_success" = "true" ]; then
    echo "✓ All fuzzing tests passed"
    exit 0
else
    echo "✗ Some fuzzing tests failed or found crashes"
    echo "Artifacts saved in: $ARTIFACT_DIR"
    exit 1
fi