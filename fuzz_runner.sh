#!/bin/bash

# IronChat Fuzzing Test Runner
# This script runs comprehensive fuzzing campaigns for IRC message parsing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FUZZ_DURATION=${FUZZ_DURATION:-60}  # Default 60 seconds per target
PARALLEL_JOBS=${PARALLEL_JOBS:-1}   # Number of parallel fuzzing jobs
OUTPUT_DIR="fuzz_output"
CORPUS_DIR="fuzz_corpus"

# Available fuzz targets
FUZZ_TARGETS=(
    "fuzz_irc_message_parsing"
    "fuzz_tag_parsing"  
    "fuzz_command_validation"
    "fuzz_connection_handling"
    "fuzz_parameter_parsing"
)

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    IronChat Security Fuzzing   ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_section() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_section "Checking dependencies..."
    
    if ! command -v cargo-fuzz &> /dev/null; then
        print_error "cargo-fuzz not found. Please install it with: cargo install cargo-fuzz"
        exit 1
    fi
    
    print_success "Dependencies check passed"
}

setup_directories() {
    print_section "Setting up output directories..."
    
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$CORPUS_DIR"
    
    for target in "${FUZZ_TARGETS[@]}"; do
        mkdir -p "$CORPUS_DIR/$target"
        mkdir -p "$OUTPUT_DIR/$target"
    done
    
    print_success "Directories created"
}

create_seed_corpus() {
    print_section "Creating seed corpus..."
    
    # IRC message parsing seeds
    cat > "$CORPUS_DIR/fuzz_irc_message_parsing/basic.txt" << 'EOF'
PRIVMSG #channel :Hello world
EOF
    
    cat > "$CORPUS_DIR/fuzz_irc_message_parsing/with_tags.txt" << 'EOF'
@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Tagged message
EOF
    
    cat > "$CORPUS_DIR/fuzz_irc_message_parsing/with_prefix.txt" << 'EOF'
:nick!user@host.com PRIVMSG #channel :Message with prefix
EOF
    
    cat > "$CORPUS_DIR/fuzz_irc_message_parsing/complex.txt" << 'EOF'
@id=123;time=2023-01-01T00:00:00.000Z :nick!user@host.com PRIVMSG #channel :Complex message
EOF
    
    # Tag parsing seeds
    cat > "$CORPUS_DIR/fuzz_tag_parsing/escaped_tags.txt" << 'EOF'
@key=value\swith\sspace;empty=;special=\:\\\r\n NOTICE * :test
EOF
    
    # Command validation seeds
    cat > "$CORPUS_DIR/fuzz_command_validation/numeric.txt" << 'EOF'
:server.com 001 nick :Welcome message
EOF
    
    cat > "$CORPUS_DIR/fuzz_command_validation/alpha.txt" << 'EOF'
JOIN #channel key
EOF
    
    # Connection handling seeds
    cat > "$CORPUS_DIR/fuzz_connection_handling/ping.txt" << 'EOF'
PING :server.com
EOF
    
    cat > "$CORPUS_DIR/fuzz_connection_handling/multiline.txt" << 'EOF'
PRIVMSG #test :Line 1
PRIVMSG #test :Line 2
EOF
    
    # Parameter parsing seeds
    cat > "$CORPUS_DIR/fuzz_parameter_parsing/many_params.txt" << 'EOF'
MODE #channel +o nick1 nick2 nick3 nick4 nick5
EOF
    
    cat > "$CORPUS_DIR/fuzz_parameter_parsing/trailing.txt" << 'EOF'
PRIVMSG #channel :This is a trailing parameter with spaces
EOF
    
    print_success "Seed corpus created"
}

run_single_fuzz() {
    local target=$1
    local duration=$2
    
    print_section "Fuzzing target: $target (${duration}s)"
    
    cd fuzz
    
    # Run the fuzzer with specified duration
    timeout "${duration}s" cargo fuzz run "$target" \
        --jobs="$PARALLEL_JOBS" \
        -- \
        -artifact_prefix="../$OUTPUT_DIR/$target/" \
        -dict=../fuzz_dictionary.txt \
        -print_final_stats=1 \
        -rss_limit_mb=2048 \
        2>&1 | tee "../$OUTPUT_DIR/$target/fuzz.log" || {
        
        # Check if timeout or actual error
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_success "Fuzzing completed for $target (timeout reached)"
        else
            print_error "Fuzzing failed for $target with exit code $exit_code"
            return $exit_code
        fi
    }
    
    cd ..
}

run_all_fuzz_targets() {
    print_section "Running all fuzz targets..."
    
    local total_targets=${#FUZZ_TARGETS[@]}
    local current=0
    
    for target in "${FUZZ_TARGETS[@]}"; do
        current=$((current + 1))
        echo -e "${BLUE}[${current}/${total_targets}]${NC} Running $target"
        
        if ! run_single_fuzz "$target" "$FUZZ_DURATION"; then
            print_error "Failed to run $target"
            continue
        fi
    done
    
    print_success "All fuzz targets completed"
}

create_fuzz_dictionary() {
    print_section "Creating fuzzing dictionary..."
    
    cat > fuzz_dictionary.txt << 'EOF'
# IRC Commands
"PRIVMSG"
"NOTICE" 
"JOIN"
"PART"
"QUIT"
"NICK"
"USER"
"PASS"
"PING"
"PONG"
"KICK"
"MODE"
"TOPIC"
"INVITE"
"WHO"
"WHOIS"
"LIST"

# Common IRC numeric codes
"001"
"002"
"003"
"004"
"005"
"401"
"403"
"404"
"421"
"461"
"462"
"464"
"473"
"474"
"475"

# IRC special characters
":"
"@"
";"
"="
"!"
"#"
"&"
"+"
"-"

# Control characters
"\r"
"\n"
"\r\n"
"\0"
"\x01"

# Tag keys
"time"
"id"
"account"
"batch"
"label"
"msgid"
"react"

# Escape sequences
"\\s"
"\\:"
"\\\\"
"\\r"
"\\n"

# Common channel prefixes
"#"
"&"
"+"
"!"

# User modes
"+o"
"+v"
"+h"
"+a"
"+q"
"-o"
"-v"

# Channel modes
"+b"
"+e"
"+I"
"+l"
"+k"
"+m"
"+n"
"+s"
"+t"
EOF
    
    print_success "Fuzzing dictionary created"
}

analyze_results() {
    print_section "Analyzing fuzzing results..."
    
    echo -e "${BLUE}Fuzzing Summary:${NC}"
    echo "=================="
    
    for target in "${FUZZ_TARGETS[@]}"; do
        local log_file="$OUTPUT_DIR/$target/fuzz.log"
        local artifacts_dir="$OUTPUT_DIR/$target"
        
        if [[ -f "$log_file" ]]; then
            echo -e "${YELLOW}$target:${NC}"
            
            # Extract statistics from log
            local execs=$(grep -o "exec/s: [0-9]*" "$log_file" | tail -1 | cut -d' ' -f2 || echo "N/A")
            local corpus_size=$(grep -o "corpus: [0-9]*" "$log_file" | tail -1 | cut -d' ' -f2 || echo "N/A")
            
            echo "  Executions/sec: $execs"
            echo "  Corpus size: $corpus_size"
            
            # Check for artifacts (crashes, hangs, etc.)
            local artifacts=$(find "$artifacts_dir" -name "crash-*" -o -name "leak-*" -o -name "timeout-*" 2>/dev/null | wc -l)
            if [[ $artifacts -gt 0 ]]; then
                echo -e "  ${RED}Artifacts found: $artifacts${NC}"
                echo "  Files:"
                find "$artifacts_dir" -name "crash-*" -o -name "leak-*" -o -name "timeout-*" 2>/dev/null | sed 's/^/    /'
            else
                echo -e "  ${GREEN}No crashes found${NC}"
            fi
            echo
        fi
    done
}

run_minimization() {
    print_section "Running crash minimization..."
    
    for target in "${FUZZ_TARGETS[@]}"; do
        local artifacts_dir="$OUTPUT_DIR/$target"
        local crashes=$(find "$artifacts_dir" -name "crash-*" 2>/dev/null)
        
        if [[ -n "$crashes" ]]; then
            print_section "Minimizing crashes for $target"
            
            for crash in $crashes; do
                local minimized="${crash}.minimized"
                echo "Minimizing $crash..."
                
                cd fuzz
                cargo fuzz tmin "$target" "$crash" -- -max_len=1024 > "$minimized" 2>/dev/null || true
                cd ..
                
                if [[ -f "$minimized" ]]; then
                    print_success "Minimized: $minimized"
                fi
            done
        fi
    done
}

show_usage() {
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo
    echo "Commands:"
    echo "  all          Run all fuzz targets (default)"
    echo "  <target>     Run specific fuzz target"
    echo "  analyze      Analyze existing results"
    echo "  minimize     Minimize found crashes"
    echo "  clean        Clean output directories"
    echo
    echo "Options:"
    echo "  -d DURATION  Fuzzing duration in seconds (default: 60)"
    echo "  -j JOBS      Number of parallel jobs (default: 1)"
    echo "  -h           Show this help"
    echo
    echo "Available targets:"
    for target in "${FUZZ_TARGETS[@]}"; do
        echo "  - $target"
    done
    echo
    echo "Examples:"
    echo "  $0 -d 300 fuzz_irc_message_parsing"
    echo "  $0 -j 4 all"
    echo "  FUZZ_DURATION=600 $0"
}

main() {
    local command="all"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--duration)
                FUZZ_DURATION="$2"
                shift 2
                ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            clean)
                print_section "Cleaning output directories..."
                rm -rf "$OUTPUT_DIR" "$CORPUS_DIR" fuzz_dictionary.txt
                print_success "Cleaned"
                exit 0
                ;;
            analyze)
                analyze_results
                exit 0
                ;;
            minimize)
                run_minimization
                exit 0
                ;;
            all|fuzz_irc_message_parsing|fuzz_tag_parsing|fuzz_command_validation|fuzz_connection_handling|fuzz_parameter_parsing)
                command="$1"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_header
    
    check_dependencies
    setup_directories
    create_seed_corpus
    create_fuzz_dictionary
    
    case "$command" in
        "all")
            run_all_fuzz_targets
            ;;
        *)
            if [[ " ${FUZZ_TARGETS[*]} " =~ " ${command} " ]]; then
                run_single_fuzz "$command" "$FUZZ_DURATION"
            else
                print_error "Unknown target: $command"
                exit 1
            fi
            ;;
    esac
    
    analyze_results
    
    print_success "Fuzzing campaign completed!"
    echo
    echo "Results are available in: $OUTPUT_DIR"
    echo "To analyze results later, run: $0 analyze"
    echo "To minimize crashes, run: $0 minimize"
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi