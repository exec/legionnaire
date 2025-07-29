#!/bin/bash

# Quick Fuzzing Script for IronChat
# Runs a short fuzzing session to quickly check for obvious issues

set -euo pipefail

DURATION=${1:-10}  # Default 10 seconds
TARGET=${2:-fuzz_irc_message_parsing}  # Default target

echo "Running quick fuzz test..."
echo "Target: $TARGET"
echo "Duration: ${DURATION}s"
echo

# Check if cargo-fuzz is available
if ! command -v cargo-fuzz &> /dev/null; then
    echo "ERROR: cargo-fuzz not found. Install with: cargo install cargo-fuzz"
    exit 1
fi

# Create basic seed if needed
mkdir -p fuzz_corpus/$TARGET
if [[ ! -f "fuzz_corpus/$TARGET/basic.txt" ]]; then
    echo "PRIVMSG #test :hello world" > "fuzz_corpus/$TARGET/basic.txt"
fi

cd fuzz

echo "Starting fuzzing..."
timeout "${DURATION}s" cargo fuzz run "$TARGET" -- -print_final_stats=1 || {
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "Fuzzing completed (timeout reached)"
    else
        echo "Fuzzing failed with exit code $exit_code"
        exit $exit_code
    fi
}

echo
echo "Quick fuzz test completed!"
echo "For comprehensive testing, use: ./fuzz_runner.sh"