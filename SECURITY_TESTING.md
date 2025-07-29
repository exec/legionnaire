# IronChat Security Testing

This document describes the comprehensive security testing framework for IronChat, designed to validate the client's robustness against malicious and malformed IRC messages.

## Overview

The security testing framework includes:

1. **Malicious Server (`tests/malicious_server.rs`)** - A test IRC server that sends crafted malicious messages
2. **Integration Tests (`tests/integration_security_tests.rs`)** - End-to-end security validation
3. **Security Test Runner (`tests/security_test_runner.rs`)** - Comprehensive test orchestration
4. **Standalone Test Runner (`tests/run_security_tests.rs`)** - Command-line security validation

## Quick Start

### Running All Security Tests

```bash
# Run all security tests with verbose output
cargo test --test run_security_tests -- --verbose

# Run with fail-fast (stop on first failure)
cargo test --test run_security_tests -- --fail-fast

# Run specific security test categories
cargo test test_message_parsing_security
cargo test test_buffer_overflow_protection
cargo test test_injection_attacks
```

### Running Integration Tests

```bash
# Run integration security tests
cargo test --test integration_security_tests

# Run specific integration tests
cargo test test_client_security_against_malicious_server
cargo test test_comprehensive_security_validation
```

## Security Test Categories

### 1. Message Parsing Security

Tests that the IRC message parser properly validates and rejects malicious input:

- **Oversized Messages**: Messages exceeding RFC limits (512 bytes)
- **Invalid Characters**: Null bytes, control characters, non-ASCII
- **Malformed Structure**: Invalid tags, prefixes, commands
- **Boundary Conditions**: Empty messages, whitespace-only input

**Critical Tests:**
```rust
// Should reject oversized messages
let oversized = "A".repeat(1000);
assert!(oversized.parse::<IrcMessage>().is_err());

// Should reject null byte injection
let null_injection = "PRIVMSG #test :hello\0world";
assert!(null_injection.parse::<IrcMessage>().is_err());
```

### 2. Buffer Overflow Protection

Validates protection against buffer overflow attacks:

- **Huge Messages**: Extremely large message bodies
- **Huge Tags**: IRCv3 tags exceeding limits
- **Parameter Flooding**: Excessive number of parameters
- **Memory Exhaustion**: Tests for memory leaks

**Test Cases:**
- Messages up to 100KB in size
- Tag sections with thousands of tags
- Commands with 50+ parameters
- Repeated parsing operations

### 3. Injection Attack Prevention

Tests against command injection and protocol confusion:

- **Command Injection**: Embedded IRC commands in parameters
- **CRLF Injection**: Carriage return/line feed injection
- **Null Byte Injection**: Null byte attacks
- **Tag Injection**: Malicious tag content

**Example Attacks Tested:**
```
PRIVMSG #test :hello\r\nQUIT :injected\r\n
NICK attacker\r\nJOIN #admin\r\n
@evil=value\r\nQUIT :injected PRIVMSG #test :hello
```

### 4. Protocol Confusion Protection

Validates rejection of non-IRC protocols:

- **HTTP Requests**: `GET / HTTP/1.1`
- **SMTP Commands**: `EHLO example.com`
- **Binary Data**: Random binary sequences
- **Other Protocols**: FTP, POP3, Telnet escape sequences

### 5. DoS Protection

Performance and resource exhaustion tests:

- **Parsing Performance**: 10,000+ messages in under 500ms
- **Memory Usage**: No unbounded memory growth
- **CPU Usage**: Efficient rejection of invalid input
- **Resource Limits**: Proper enforcement of all limits

### 6. TLS Security (Future)

Tests for TLS-specific security:

- **Certificate Validation**: Proper cert chain validation
- **Downgrade Attacks**: Prevention of TLS downgrade
- **Cipher Suite Security**: Strong cipher enforcement
- **SNI Validation**: Server name indication security

## Test Results Interpretation

### Success Criteria

A security test suite is considered successful when:

- **Success Rate ≥ 95%**: At least 95% of tests pass
- **No Critical Failures**: All injection and overflow tests pass
- **Performance Requirements**: Parsing meets performance targets
- **Standards Compliance**: RFC 2812 and IRCv3 compliance

### Example Output

```
IronChat Security Test Report
================================

Overall Results:
  Total Tests: 45
  Passed: 44
  Failed: 1
  Success Rate: 97.8%
  Duration: 125ms

Message Parsing: Tests: 12 passed, 0 failed (100.0% success rate)
Buffer Overflow Protection: Tests: 8 passed, 0 failed (100.0% success rate)
Injection Attack Protection: Tests: 10 passed, 1 failed (90.0% success rate)
Protocol Confusion Protection: Tests: 8 passed, 0 failed (100.0% success rate)
DoS Protection: Tests: 7 passed, 0 failed (100.0% success rate)
```

## Creating New Security Tests

### Adding Message Parser Tests

```rust
// Add to tests/security_test_runner.rs
let test_cases = vec![
    ("test_name", "malicious_message", false), // should fail
    ("valid_test", "PRIVMSG #test :hello", true), // should pass
];
```

### Adding Integration Tests

```rust
// Add to tests/integration_security_tests.rs
#[tokio::test]
async fn test_new_attack_vector() {
    let malicious_input = "ATTACK_VECTOR_HERE";
    let result = malicious_input.parse::<IrcMessage>();
    assert!(result.is_err(), "Attack should be rejected");
}
```

### Adding Malicious Server Tests

```rust
// Add to tests/malicious_server.rs TestCase vector
TestCase {
    name: "new_attack".to_string(),
    message: "MALICIOUS_MESSAGE\r\n".to_string(),
    expected_behavior: ExpectedBehavior::Reject,
    description: "Description of the attack".to_string(),
}
```

## Continuous Integration

### GitHub Actions

```yaml
name: Security Tests
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run Security Tests
        run: cargo test --test run_security_tests -- --verbose
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
cargo test --test run_security_tests --quiet
if [ $? -ne 0 ]; then
    echo "Security tests failed! Commit rejected."
    exit 1
fi
```

## Security Test Development Guidelines

### 1. Test Design Principles

- **Comprehensive Coverage**: Test all attack vectors
- **Realistic Threats**: Based on real-world IRC attacks
- **Performance Aware**: Tests should complete quickly
- **Maintainable**: Clear test names and descriptions

### 2. Adding New Attack Vectors

When adding new security tests:

1. Research the attack vector thoroughly
2. Create minimal reproducible test cases
3. Verify the client properly rejects the attack
4. Add performance benchmarks if relevant
5. Document the attack in test descriptions

### 3. Test Maintenance

- **Regular Updates**: Keep tests current with new threats
- **Performance Monitoring**: Track test execution time
- **Coverage Analysis**: Ensure all code paths are tested
- **Documentation**: Keep this document updated

## Security Standards Compliance

### RFC 2812 (IRC Protocol)

- Message length limits (512 bytes)
- Character set restrictions (ASCII only)
- Line termination requirements (CRLF)
- Command format validation

### IRCv3 Specifications

- Tag length limits (8191 bytes)
- Tag key validation
- Capability negotiation security
- Message tags escaping

### Security Best Practices

- Input validation at all boundaries
- Fail-safe defaults (reject unknown input)
- Resource consumption limits
- Error message information disclosure prevention

## Troubleshooting

### Common Issues

**Test Failures:**
- Check that the client code is properly rejecting malicious input
- Verify test expectations match security requirements
- Review error messages for clues about validation failures

**Performance Issues:**
- Profile parsing code for bottlenecks
- Check for memory leaks in message handling
- Verify efficient rejection of invalid input

**Integration Problems:**
- Ensure test server ports are available
- Check firewall/network configuration
- Verify TLS certificate generation works

### Debugging Tests

```bash
# Run with detailed output
RUST_LOG=debug cargo test --test run_security_tests -- --verbose

# Run specific test category
cargo test test_buffer_overflow_protection -- --nocapture

# Profile performance
cargo test benchmark_security_performance -- --nocapture
```

## Contributing

When contributing new security tests:

1. Follow the existing test structure and naming conventions
2. Add comprehensive documentation for new attack vectors  
3. Ensure tests are deterministic and don't rely on external services
4. Update this documentation with new test categories
5. Verify tests pass consistently across different platforms

## References

- [RFC 2812 - Internet Relay Chat: Client Protocol](https://tools.ietf.org/html/rfc2812)
- [IRCv3 Specifications](https://ircv3.net/specs/)
- [OWASP Input Validation Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)