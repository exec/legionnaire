# IronChat Security Fuzzing Guide

This document describes the fuzzing infrastructure for IronChat IRC client, designed to discover parsing vulnerabilities, crashes, and security issues.

## Overview

The fuzzing setup targets the core IRC message parsing functionality, focusing on:
- `IrcMessage::from_str` function and related parsing code
- Tag parsing and validation
- Command validation
- Connection-level message handling
- Parameter parsing edge cases

## Quick Start

### Prerequisites

1. Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

2. Ensure you have a recent Rust nightly toolchain:
```bash
rustup install nightly
rustup default nightly
```

### Running Quick Tests

For a quick security check (10 seconds):
```bash
./quick_fuzz.sh
```

For a specific target:
```bash
./quick_fuzz.sh 30 fuzz_tag_parsing
```

### Comprehensive Fuzzing

Run all fuzz targets for 5 minutes each:
```bash
./fuzz_runner.sh -d 300
```

Run with multiple parallel jobs:
```bash
./fuzz_runner.sh -j 4 -d 600
```

### CI/CD Integration

For automated testing in CI pipelines:
```bash
./ci_fuzz.sh
```

Environment variables:
- `CI_FUZZ_DURATION`: Duration per target (default: 30s)
- `FAIL_ON_CRASH`: Whether to fail CI on crashes (default: true)

## Fuzz Targets

### 1. `fuzz_irc_message_parsing`
**Primary target for `IrcMessage::from_str`**

Tests:
- Basic message parsing with various formats
- UTF-8 validation and malformed input
- Line ending handling (CRLF, LF)
- Whitespace edge cases
- Binary data rejection

**Key attack vectors:**
- Buffer overflow attempts
- Malformed UTF-8 sequences
- Invalid line endings
- Empty/null inputs

### 2. `fuzz_tag_parsing`
**Targets IRCv3 tag parsing and validation**

Tests:
- Tag key validation (length, character set)
- Tag value escaping/unescaping
- Tag separator handling
- Maximum tag length enforcement
- Complex tag combinations

**Key attack vectors:**
- Tag length bombs (8191+ character limit)
- Invalid escape sequences
- Malformed tag separators
- Non-ASCII characters in tags

### 3. `fuzz_command_validation`
**Focuses on IRC command validation**

Tests:
- Alphanumeric command validation
- 3-digit numeric code validation
- Command length limits (32 characters)
- Prefix handling
- Case sensitivity

**Key attack vectors:**
- Oversized commands
- Invalid command characters
- Numeric code edge cases
- Command injection attempts

### 4. `fuzz_connection_handling`
**Simulates real connection message processing**

Tests:
- Multi-line message processing
- Connection-level length limits
- ASCII validation
- Message fragmentation
- Common IRC command fuzzing

**Key attack vectors:**
- Message length bombs
- Non-ASCII injection
- Protocol confusion
- Buffer exhaustion

### 5. `fuzz_parameter_parsing`
**Targets parameter and trailing message parsing**

Tests:
- Maximum parameter count (15 limit)
- Trailing parameter handling
- Colon parsing edge cases
- Parameter length validation
- Special character handling

**Key attack vectors:**
- Parameter count overflow
- Trailing parameter bombs
- Colon confusion attacks
- Control character injection

## Understanding Results

### Normal Output
```
#1048576	INITED cov: 156 ft: 157 corp: 1/13b exec/s: 524288 rss: 25Mb
#2097152	NEW    cov: 158 ft: 159 corp: 2/26b lim: 4096 exec/s: 524288 rss: 25Mb
```

- `cov`: Code coverage (higher is better)
- `ft`: Features covered
- `corp`: Corpus size (inputs found)
- `exec/s`: Executions per second
- `rss`: Memory usage

### Crash Detection
If a crash is found:
```
==1234==ERROR: AddressSanitizer: heap-buffer-overflow
```

Artifacts are saved in:
- `fuzz_output/<target>/crash-<hash>`
- `fuzz_output/<target>/leak-<hash>`
- `fuzz_output/<target>/timeout-<hash>`

### Analysis Commands

View results summary:
```bash
./fuzz_runner.sh analyze
```

Minimize crashes:
```bash
./fuzz_runner.sh minimize
```

Manual crash reproduction:
```bash
cd fuzz
cargo fuzz run fuzz_irc_message_parsing fuzz_output/fuzz_irc_message_parsing/crash-xyz
```

## Advanced Usage

### Custom Duration and Parallelization

Long-running fuzzing campaign:
```bash
FUZZ_DURATION=3600 PARALLEL_JOBS=8 ./fuzz_runner.sh
```

### Target-Specific Testing

Focus on a specific vulnerability area:
```bash
./fuzz_runner.sh -d 1800 fuzz_tag_parsing
```

### Corpus Management

The fuzzer automatically creates seed corpus files, but you can add custom test cases:

```bash
# Add custom IRC messages to test
echo "@custom=value PRIVMSG #test :custom message" > fuzz_corpus/fuzz_tag_parsing/custom.txt
```

### Dictionary Enhancement

Edit `fuzz_dictionary.txt` to add domain-specific tokens:
```
"CUSTOM_COMMAND"
"special_tag"
"#custom_channel"
```

## Security Focus Areas

### 1. Input Validation Bypasses
The fuzzer tests for:
- Length limit circumvention
- Character set validation bypasses
- Encoding confusion attacks

### 2. Parser State Confusion
Tests for:
- Incomplete message handling
- State machine edge cases
- Context switching vulnerabilities

### 3. Memory Safety
Focuses on:
- Buffer overflow conditions
- Integer overflow in length calculations
- Use-after-free scenarios
- Memory exhaustion attacks

### 4. Protocol Compliance
Validates:
- RFC 1459 compliance
- IRCv3 specification adherence
- Error handling robustness

## Interpreting Security Results

### Critical Issues (Immediate Fix Required)
- **Crashes**: Any crash indicates a potential security vulnerability
- **Hangs/Timeouts**: May indicate denial of service vulnerabilities
- **Memory Leaks**: Could lead to resource exhaustion

### Medium Priority Issues
- **Parsing Inconsistencies**: May lead to protocol confusion
- **Validation Bypasses**: Could allow malformed data through

### Performance Issues
- **Slow Parsing**: May indicate algorithmic complexity attacks
- **Memory Spikes**: Could indicate inefficient memory usage

## Integration with Development Workflow

### Pre-commit Hook
Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
echo "Running security fuzzing..."
./ci_fuzz.sh
```

### Continuous Integration
Add to CI pipeline:
```yaml
- name: Security Fuzzing
  run: |
    ./ci_fuzz.sh
  env:
    CI_FUZZ_DURATION: 60
```

### Regression Testing
After fixing issues:
```bash
# Test specific fix
./quick_fuzz.sh 120 fuzz_irc_message_parsing

# Full regression test
./fuzz_runner.sh -d 300
```

## Troubleshooting

### Common Issues

**"cargo-fuzz not found"**
```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

**"Failed to compile fuzz target"**
- Ensure dependencies are up to date: `cargo update`
- Check Rust nightly version: `rustup update nightly`

**"No crashes found but expecting issues"**
- Increase duration: `-d 3600`
- Use more parallel jobs: `-j 8`
- Check seed corpus quality

**"Too many crashes"**
- Review recent code changes
- Check for regression in input validation
- Consider reducing fuzzing intensity

### Performance Tuning

For better performance:
```bash
# Increase memory limit
cargo fuzz run target -- -rss_limit_mb=4096

# Adjust corpus size
cargo fuzz run target -- -entropic=0

# Focus on coverage
cargo fuzz run target -- -shrink=1
```

## Security Reporting

If fuzzing discovers security vulnerabilities:

1. **Stop fuzzing** the affected target
2. **Document the crash** with minimal reproduction case
3. **Assess impact** (DoS, RCE, information disclosure)
4. **Fix the vulnerability** in the parsing code
5. **Add regression test** to prevent reoccurrence
6. **Re-run fuzzing** to verify fix

## Best Practices

### Regular Fuzzing Schedule
- **Daily**: Quick 30-second runs during development
- **Weekly**: 1-hour comprehensive fuzzing
- **Release**: 6-24 hour fuzzing campaigns

### Seed Corpus Maintenance
- Add real-world IRC messages to corpus
- Include edge cases from bug reports
- Update corpus after protocol changes

### Coverage Analysis
- Monitor code coverage trends
- Identify untested code paths
- Add targeted test cases for low coverage areas

## Additional Resources

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [cargo-fuzz Book](https://rust-fuzz.github.io/book/)
- [IRC Protocol RFC 1459](https://tools.ietf.org/html/rfc1459)
- [IRCv3 Specifications](https://ircv3.net/specs/)

---

**⚠️ Security Notice**: Fuzzing may discover security vulnerabilities. Handle all findings as potentially sensitive and follow responsible disclosure practices.