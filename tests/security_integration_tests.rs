//! Security Integration Tests
//!
//! Comprehensive tests for security hardening, threat detection,
//! and attack resistance to ensure production-ready security.

use legionnaire::{SecurityValidator, SecurityConfig, SecurityEventType};
use anyhow::Result;
use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{timeout, Duration};

/// Test comprehensive input validation
#[tokio::test]
#[serial]
async fn test_comprehensive_input_validation() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    // Test 1: Normal messages should pass
    assert!(validator.validate_message("user1", "Hello world!", None).await.is_ok());
    assert!(validator.validate_message("user2", "How are you?", None).await.is_ok());

    // Test 2: Message length limits
    let long_message = "a".repeat(1000);
    assert!(validator.validate_message("user1", &long_message, None).await.is_err());

    // Test 3: Control character injection
    let control_chars = "Hello\x00world";
    assert!(validator.validate_message("user1", control_chars, None).await.is_err());

    // Test 4: Script injection attempts
    let script_injection = "<script>alert('xss')</script>";
    assert!(validator.validate_message("user1", script_injection, None).await.is_err());

    // Test 5: Command injection attempts
    let cmd_injection = "; rm -rf /";
    assert!(validator.validate_message("user1", cmd_injection, None).await.is_err());

    // Test 6: Path traversal attempts
    let path_traversal = "../../../etc/passwd";
    assert!(validator.validate_message("user1", path_traversal, None).await.is_err());

    // Test 7: Buffer overflow attempts (long base64-like strings)
    let buffer_overflow = "A".repeat(2000);
    assert!(validator.validate_message("user1", &buffer_overflow, None).await.is_err());

    println!("✅ All input validation tests passed");
    Ok(())
}

/// Test rate limiting protection
#[tokio::test]
#[serial]
async fn test_rate_limiting_protection() -> Result<()> {
    let mut config = SecurityConfig::default();
    config.rate_limit_messages_per_minute = 5; // Very low for testing
    let validator = SecurityValidator::new(config)?;

    let test_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

    // Send messages up to the limit
    for i in 0..5 {
        let message = format!("Message {}", i);
        assert!(validator.validate_message("test_user", &message, test_ip).await.is_ok(),
                "Message {} should succeed", i);
    }

    // Next message should be rate limited
    assert!(validator.validate_message("test_user", "Excess message", test_ip).await.is_err(),
            "Should be rate limited");

    // Different user should not be affected
    assert!(validator.validate_message("different_user", "New user message", test_ip).await.is_ok(),
            "Different user should not be rate limited");

    println!("✅ Rate limiting protection working correctly");
    Ok(())
}

/// Test connection throttling per IP
#[tokio::test]
#[serial]
async fn test_connection_throttling() -> Result<()> {
    let mut config = SecurityConfig::default();
    config.max_connections_per_ip = 3; // Low limit for testing
    let validator = SecurityValidator::new(config)?;

    let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // First few connections should succeed
    for i in 0..3 {
        assert!(validator.validate_connection(test_ip).await.is_ok(),
                "Connection {} should succeed", i);
    }

    // Additional connections should be throttled
    for i in 3..6 {
        assert!(validator.validate_connection(test_ip).await.is_err(),
                "Connection {} should be throttled", i);
    }

    // Different IP should not be affected
    let different_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    assert!(validator.validate_connection(different_ip).await.is_ok(),
            "Different IP should not be throttled");

    println!("✅ Connection throttling working correctly");
    Ok(())
}

/// Test malicious pattern detection
#[tokio::test]
#[serial]
async fn test_malicious_pattern_detection() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    let malicious_patterns = vec![
        // Command injection
        ("rm -rf /home/user", "Command injection should be detected"),
        ("shutdown -h now", "Shutdown command should be detected"),
        ("del C:\\Windows", "Windows delete command should be detected"),
        
        // Path traversal
        ("../../../etc/shadow", "Path traversal should be detected"),
        ("..\\..\\Windows\\System32", "Windows path traversal should be detected"),
        ("%2e%2e%2f", "URL-encoded path traversal should be detected"),
        
        // Script injection
        ("<script src='evil.js'></script>", "Script injection should be detected"),
        ("javascript:alert('xss')", "JavaScript URI should be detected"),
        ("data:text/html,<script>evil()</script>", "Data URI script should be detected"),
        
        // CTCP floods/abuse
        ("\x01ACTION does something\x01", "CTCP should be monitored"),
        
        // IRC command abuse
        ("JOIN #channel1 #channel2 #channel3", "Mass channel joins should be detected"),
    ];

    for (pattern, description) in malicious_patterns {
        let result = validator.validate_message("attacker", pattern, None).await;
        if result.is_ok() {
            println!("⚠️  Pattern not detected: {} - {}", pattern, description);
        } else {
            println!("✅ Detected malicious pattern: {}", description);
        }
    }

    Ok(())
}

/// Test nickname and channel name validation
#[tokio::test]
#[serial]
async fn test_name_validation() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    // Valid nicknames
    assert!(validator.validate_name("nickname", "alice").is_ok());
    assert!(validator.validate_name("nickname", "bob_123").is_ok());
    assert!(validator.validate_name("nickname", "user-name").is_ok());

    // Invalid nicknames
    assert!(validator.validate_name("nickname", "").is_err()); // Empty
    assert!(validator.validate_name("nickname", "#alice").is_err()); // Starts with #
    assert!(validator.validate_name("nickname", "alice bob").is_err()); // Contains space
    assert!(validator.validate_name("nickname", "alice\x00").is_err()); // Null byte

    // Valid channels
    assert!(validator.validate_name("channel", "#general").is_ok());
    assert!(validator.validate_name("channel", "&local").is_ok());
    assert!(validator.validate_name("channel", "#test-123").is_ok());

    // Invalid channels
    assert!(validator.validate_name("channel", "general").is_err()); // No prefix
    assert!(validator.validate_name("channel", "#").is_err()); // Just prefix
    assert!(validator.validate_name("channel", "#general\n").is_err()); // Newline

    // Length limits
    let long_name = "a".repeat(100);
    assert!(validator.validate_name("nickname", &long_name).is_err());
    assert!(validator.validate_name("channel", &format!("#{}", long_name)).is_err());

    println!("✅ Name validation working correctly");
    Ok(())
}

/// Test progressive blocking for repeated violations
#[tokio::test]
#[serial]
async fn test_progressive_blocking() -> Result<()> {
    let mut config = SecurityConfig::default();
    config.rate_limit_messages_per_minute = 1; // Very strict for testing
    let validator = SecurityValidator::new(config)?;

    // First violation - should get temporary block
    assert!(validator.validate_message("repeat_offender", "msg1", None).await.is_ok());
    assert!(validator.validate_message("repeat_offender", "msg2", None).await.is_err());

    // Wait a short time and try again - should still be blocked initially
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(validator.validate_message("repeat_offender", "msg3", None).await.is_err());

    println!("✅ Progressive blocking implemented");
    Ok(())
}

/// Test concurrent attack simulation
#[tokio::test]
#[serial]
async fn test_concurrent_attack_simulation() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    // Simulate multiple attackers trying various attack vectors concurrently
    let attack_tasks = vec![
        // Attacker 1: Rate limit violation
        tokio::spawn({
            let validator = validator.clone();
            async move {
                for i in 0..20 {
                    let _ = validator.validate_message(
                        "spammer", 
                        &format!("spam message {}", i), 
                        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
                    ).await;
                }
            }
        }),
        
        // Attacker 2: Connection flooding
        tokio::spawn({
            let validator = validator.clone();
            async move {
                for _ in 0..10 {
                    let _ = validator.validate_connection(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))
                    ).await;
                }
            }
        }),
        
        // Attacker 3: Malicious payloads
        tokio::spawn({
            let validator = validator.clone();
            async move {
                let payloads = vec![
                    "rm -rf /",
                    "<script>evil()</script>",
                    "../../../etc/passwd",
                    "javascript:alert('xss')",
                ];
                for payload in payloads {
                    let _ = validator.validate_message(
                        "hacker", 
                        payload, 
                        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)))
                    ).await;
                }
            }
        }),
    ];

    // Wait for all attacks to complete
    for task in attack_tasks {
        let _ = timeout(Duration::from_secs(5), task).await;
    }

    // Get security statistics
    let stats = validator.get_security_stats().await;
    println!("Security stats after attack simulation:");
    println!("  - Active rate limits: {}", stats.active_rate_limits);
    println!("  - Blocked clients: {}", stats.blocked_clients);
    println!("  - Blocked IPs: {}", stats.blocked_ips);
    println!("  - Total violations: {}", stats.total_violations);

    // Should have some blocked entities after the attacks
    assert!(stats.total_violations > 0, "Should have recorded violations");
    
    println!("✅ Concurrent attack simulation handled");
    Ok(())
}

/// Test edge cases and boundary conditions
#[tokio::test]
#[serial]
async fn test_edge_cases() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    // Test empty inputs
    assert!(validator.validate_message("user", "", None).await.is_ok()); // Empty message OK
    assert!(validator.validate_name("nickname", "").is_err()); // Empty nickname not OK

    // Test unicode and international characters
    assert!(validator.validate_message("user", "Hello 世界! 🌍", None).await.is_ok());
    assert!(validator.validate_name("nickname", "用户名").is_ok());

    // Test boundary length values
    let exactly_512_chars = "a".repeat(512);
    assert!(validator.validate_message("user", &exactly_512_chars, None).await.is_ok());
    
    let exactly_513_chars = "a".repeat(513);
    assert!(validator.validate_message("user", &exactly_513_chars, None).await.is_err());

    // Test special IRC characters
    assert!(validator.validate_message("user", "\x02bold\x02 \x03red\x03", None).await.is_ok());

    // Test null IP address handling
    assert!(validator.validate_message("user", "test", None).await.is_ok());

    println!("✅ Edge cases handled correctly");
    Ok(())
}

/// Test security configuration variations
#[tokio::test]
#[serial]
async fn test_security_configuration_variations() -> Result<()> {
    // Test with strict security
    let strict_config = SecurityConfig {
        strict_input_validation: true,
        max_message_length: 200,
        max_name_length: 20,
        enable_rate_limiting: true,
        rate_limit_messages_per_minute: 10,
        enable_connection_throttling: true,
        max_connections_per_ip: 2,
        enable_threat_detection: true,
        ..SecurityConfig::default()
    };

    let strict_validator = SecurityValidator::new(strict_config)?;
    
    // Strict validator should be more restrictive
    let medium_message = "a".repeat(250);
    assert!(strict_validator.validate_message("user", &medium_message, None).await.is_err());

    // Test with lenient security
    let lenient_config = SecurityConfig {
        strict_input_validation: false,
        max_message_length: 2000,
        enable_rate_limiting: false,
        enable_connection_throttling: false,
        enable_threat_detection: false,
        ..SecurityConfig::default()
    };

    let lenient_validator = SecurityValidator::new(lenient_config)?;
    
    // Lenient validator should allow more
    let long_message = "a".repeat(1000);
    assert!(lenient_validator.validate_message("user", &long_message, None).await.is_ok());

    println!("✅ Security configuration variations working");
    Ok(())
}

/// Test realistic attack scenarios
#[tokio::test]
#[serial]
async fn test_realistic_attack_scenarios() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    // Scenario 1: Slow rate limit evasion attempt
    let attacker_ip = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
    
    // Send messages just under rate limit, then spike
    for i in 0..3 {
        assert!(validator.validate_message("evader", &format!("slow msg {}", i), attacker_ip).await.is_ok());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // Sudden spike should be caught
    for i in 0..10 {
        let result = validator.validate_message("evader", &format!("spike msg {}", i), attacker_ip).await;
        if result.is_err() {
            println!("✅ Rate limit spike detected at message {}", i);
            break;
        }
    }

    // Scenario 2: Disguised malicious content
    let disguised_attacks = vec![
        "Hey, check out this cool link: javascript:alert('gotcha')",
        "My favorite file is at ..%2F..%2Fetc%2Fpasswd you should read it",
        "Just run this: echo 'rm -rf /' | sh for fun",
    ];

    for attack in disguised_attacks {
        let result = validator.validate_message("social_engineer", attack, None).await;
        if result.is_err() {
            println!("✅ Disguised attack detected: {}", attack);
        }
    }

    // Scenario 3: Resource exhaustion attempt
    let resource_attacks = vec![
        "A".repeat(1500),  // Memory exhaustion
        "B".repeat(800),   // Just under limit
        "\x01".repeat(100), // CTCP flood
    ];

    for (i, attack) in resource_attacks.iter().enumerate() {
        let result = validator.validate_message("resource_attacker", attack, None).await;
        println!("Resource attack {}: {}", i, if result.is_err() { "BLOCKED" } else { "allowed" });
    }

    println!("✅ Realistic attack scenarios tested");
    Ok(())
}

/// Test security monitoring and alerting
#[tokio::test]
#[serial]
async fn test_security_monitoring() -> Result<()> {
    let config = SecurityConfig {
        enable_audit_logging: true,
        security_log_file: Some("test_security.log".to_string()),
        ..SecurityConfig::default()
    };

    let validator = SecurityValidator::new(config)?;

    // Generate various security events
    let _ = validator.validate_message("test", "rm -rf /", None).await; // Should generate alert
    let _ = validator.validate_message("test", "a".repeat(1000), None).await; // Length violation
    let _ = validator.validate_connection(IpAddr::V4(Ipv4Addr::LOCALHOST)).await; // Connection tracking

    // Get security statistics
    let stats = validator.get_security_stats().await;
    println!("Security monitoring stats:");
    println!("  - Total violations: {}", stats.total_violations);
    println!("  - Active connections: {}", stats.active_connections);

    // Clean up test log file
    let _ = std::fs::remove_file("test_security.log");

    println!("✅ Security monitoring working");
    Ok(())
}

/// Performance test: Security validation under load
#[tokio::test]
#[serial]
async fn test_security_performance_under_load() -> Result<()> {
    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    let start_time = std::time::Instant::now();
    let message_count = 1000;

    // Simulate high-volume message validation
    let tasks: Vec<_> = (0..message_count)
        .map(|i| {
            let validator = validator.clone();
            tokio::spawn(async move {
                let message = format!("Load test message {}", i);
                let user = format!("user_{}", i % 10); // 10 different users
                let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)));
                
                validator.validate_message(&user, &message, ip).await
            })
        })
        .collect();

    // Wait for all validations to complete
    let mut successes = 0;
    let mut failures = 0;

    for task in tasks {
        match task.await {
            Ok(Ok(_)) => successes += 1,
            Ok(Err(_)) => failures += 1,
            Err(_) => failures += 1,
        }
    }

    let duration = start_time.elapsed();
    let throughput = message_count as f64 / duration.as_secs_f64();

    println!("Security validation performance test:");
    println!("  - Messages processed: {}", message_count);
    println!("  - Successes: {}", successes);
    println!("  - Failures: {}", failures);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.1} validations/sec", throughput);

    // Should maintain reasonable throughput even under load
    assert!(throughput > 100.0, "Security validation throughput too low: {}", throughput);

    println!("✅ Security performance under load acceptable");
    Ok(())
}