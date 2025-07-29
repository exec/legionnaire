#!/usr/bin/env cargo test --test
//! Standalone security test runner for IronChat
//! 
//! This can be executed with: cargo test --test run_security_tests
//! Or as a standalone binary to validate client security

use std::env;
use tracing_subscriber;

mod security_test_runner;
use security_test_runner::{run_security_tests, SecurityTestRunner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let verbose = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string());
    let fail_fast = args.contains(&"--fail-fast".to_string());

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }

    println!("IronChat Security Test Suite");
    println!("===========================");
    println!();

    // Run the security tests
    match run_security_tests(verbose, fail_fast).await {
        Ok(()) => {
            println!("✅ All security tests passed!");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("❌ Security tests failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("IronChat Security Test Runner");
    println!();
    println!("USAGE:");
    println!("    cargo test --test run_security_tests [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -v, --verbose     Enable verbose output");
    println!("    --fail-fast       Stop on first test failure");
    println!("    -h, --help        Show this help message");
    println!();
    println!("DESCRIPTION:");
    println!("    Runs comprehensive security tests against the IronChat IRC client");
    println!("    to validate that it properly handles malicious and malformed input.");
    println!();
    println!("TESTS INCLUDED:");
    println!("    • Message parsing security validation");
    println!("    • Buffer overflow protection");
    println!("    • Command injection prevention");
    println!("    • Protocol confusion protection");
    println!("    • DoS attack mitigation");
    println!("    • TLS security validation");
    println!();
    println!("EXAMPLES:");
    println!("    cargo test --test run_security_tests");
    println!("    cargo test --test run_security_tests -- --verbose");
    println!("    cargo test --test run_security_tests -- --fail-fast");
}

/// Integration test that runs all security validations
#[tokio::test] 
async fn comprehensive_security_test() {
    let _ = tracing_subscriber::fmt::try_init();
    
    let runner = SecurityTestRunner::new().with_verbose(true);
    let report = runner.run_all_tests().await
        .expect("Security test runner should execute successfully");

    println!("\n{}", report.detailed_report());

    // Verify that we have good security coverage
    assert!(report.total_tests() >= 30, "Should have at least 30 security tests");
    assert!(report.success_rate() >= 0.95, "Should have at least 95% success rate");
    assert!(report.errors.is_empty(), "Should have no test execution errors");
    
    // Verify specific security categories are tested
    let category_names: Vec<&String> = report.categories.iter().map(|(name, _)| name).collect();
    assert!(category_names.iter().any(|name| name.contains("Message Parsing")), 
        "Should test message parsing security");
    assert!(category_names.iter().any(|name| name.contains("Buffer Overflow")), 
        "Should test buffer overflow protection");
    assert!(category_names.iter().any(|name| name.contains("Injection")), 
        "Should test injection attack protection");
    assert!(category_names.iter().any(|name| name.contains("Protocol Confusion")), 
        "Should test protocol confusion protection");
    assert!(category_names.iter().any(|name| name.contains("DoS")), 
        "Should test DoS protection");
}

/// Test specific IRC security standards compliance
#[tokio::test]
async fn test_irc_security_standards() {
    use ironchat::message::IrcMessage;
    
    // Test RFC 2812 compliance with security extensions
    
    // 1. Message length limits (RFC 2812 Section 2.3)
    let max_message = "A".repeat(512);
    assert!(max_message.parse::<IrcMessage>().is_err(), 
        "Messages over 512 bytes should be rejected");
    
    // 2. Character set restrictions (RFC 2812 Section 2.2)
    let non_ascii = "PRIVMSG #test :héllo";
    assert!(non_ascii.parse::<IrcMessage>().is_err(),
        "Non-ASCII characters should be rejected");
    
    // 3. Line termination (RFC 2812 Section 2.3)
    let no_crlf = "PRIVMSG #test :hello";
    assert!(no_crlf.parse::<IrcMessage>().is_err(),
        "Messages without CRLF should be rejected");
    
    // 4. IRCv3 tag limits (IRCv3 spec)
    let max_tags = format!("@{} PRIVMSG #test :hello", "a=b;".repeat(2000));
    assert!(max_tags.parse::<IrcMessage>().is_err(),
        "Tag sections over 8191 bytes should be rejected");
    
    // 5. Security-critical character filtering
    let null_byte = "PRIVMSG #test :hello\0world";
    assert!(null_byte.parse::<IrcMessage>().is_err(),
        "Null bytes should be rejected");
    
    let cr_injection = "PRIVMSG #test :hello\rworld";
    assert!(cr_injection.parse::<IrcMessage>().is_err(),
        "Carriage return injection should be rejected");
    
    let lf_injection = "PRIVMSG #test :hello\nworld";
    assert!(lf_injection.parse::<IrcMessage>().is_err(),
        "Line feed injection should be rejected");
}

/// Benchmark security validation performance
#[tokio::test]
async fn benchmark_security_performance() {
    use std::time::Instant;
    
    let start = Instant::now();
    
    // Parse 1000 valid messages
    for i in 0..1000 {
        let message = format!("PRIVMSG #test{} :Hello world {}", i % 10, i);
        message.parse::<IrcMessage>().expect("Valid message should parse");
    }
    
    let valid_duration = start.elapsed();
    
    let start = Instant::now();
    
    // Parse 1000 invalid messages (should fail fast)
    for i in 0..1000 {
        let message = format!("PRIVMSG #test{} :hello\0world {}", i % 10, i);
        assert!(message.parse::<IrcMessage>().is_err());
    }
    
    let invalid_duration = start.elapsed();
    
    println!("Performance benchmark:");
    println!("  Valid messages: {:?} for 1000 messages", valid_duration);
    println!("  Invalid messages: {:?} for 1000 messages", invalid_duration);
    
    // Performance requirements
    assert!(valid_duration.as_millis() < 100, 
        "Valid message parsing too slow: {:?}", valid_duration);
    assert!(invalid_duration.as_millis() < 100, 
        "Invalid message rejection too slow: {:?}", invalid_duration);
}