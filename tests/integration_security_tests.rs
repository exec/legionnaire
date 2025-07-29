use ironchat::message::IrcMessage;
use ironchat::error::{IronError, Result};
use ironchat::connection::SecureConnection;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt, AsyncBufReadExt, BufReader};
use std::time::Duration;
use tracing::{debug, info, warn, error};
use std::sync::Arc;
use tokio::sync::Mutex;

mod malicious_server;
use malicious_server::{MaliciousIrcServer, TestResults, ExpectedBehavior};

/// Integration tests for IRC client security against malicious servers
#[tokio::test]
async fn test_client_security_against_malicious_server() {
    // Initialize tracing for test output
    let _ = tracing_subscriber::fmt::try_init();

    info!("Starting client security integration tests");

    // Test with plain TCP first
    let tcp_results = test_tcp_security().await.expect("TCP security tests failed");
    info!("TCP Security Test Results: {}", tcp_results.summary());

    // Test message parsing security
    malicious_server::test_message_parsing_security().await
        .expect("Message parsing security tests failed");

    // Verify that critical security tests passed
    assert!(tcp_results.passed > 0, "No TCP security tests passed");
    assert!(tcp_results.success_rate() > 0.8, "Too many security tests failed");

    info!("All security integration tests completed successfully");
}

/// Test client security against malicious TCP messages
async fn test_tcp_security() -> Result<TestResults> {
    let listener = TcpListener::bind("127.0.0.1:0").await
        .map_err(|e| IronError::Connection(format!("Failed to bind test server: {}", e)))?;

    let server_addr = listener.local_addr()
        .map_err(|e| IronError::Connection(format!("Failed to get server address: {}", e)))?;

    let mut results = TestResults::new();

    // Define malicious test cases
    let test_cases = vec![
        // Oversized messages
        (
            "oversized_message",
            format!("PRIVMSG #test :{}\r\n", "A".repeat(1000)),
            ExpectedBehavior::Reject,
        ),
        // Null bytes
        (
            "null_byte_attack",
            "PRIVMSG #test :hello\0world\r\n".to_string(),
            ExpectedBehavior::Reject,
        ),
        // Command injection
        (
            "command_injection",
            "PRIVMSG #test :hello\r\nQUIT :injected\r\n".to_string(),
            ExpectedBehavior::Reject,
        ),
        // Invalid commands
        (
            "invalid_command",
            "INVALID@CMD #test :hello\r\n".to_string(),
            ExpectedBehavior::Reject,
        ),
        // Malformed prefix
        (
            "malformed_prefix",
            ":nick name!user@host PRIVMSG #test :hello\r\n".to_string(),
            ExpectedBehavior::Reject,
        ),
        // Too many parameters
        (
            "too_many_params",
            format!("PRIVMSG {} :hello\r\n", 
                (0..20).map(|i| format!("#ch{}", i)).collect::<Vec<_>>().join(" ")),
            ExpectedBehavior::Reject,
        ),
        // Binary data
        (
            "binary_data",
            String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD, 0xFC, 0x0D, 0x0A]).to_string(),
            ExpectedBehavior::Reject,
        ),
        // Valid message (control test)
        (
            "valid_message",
            "PRIVMSG #test :Hello world\r\n".to_string(),
            ExpectedBehavior::Accept,
        ),
    ];

    for (test_name, malicious_message, expected_behavior) in test_cases {
        info!("Running security test: {}", test_name);

        let test_result = run_single_security_test(
            &listener,
            server_addr,
            &malicious_message,
            expected_behavior,
        ).await;

        match test_result {
            Ok(passed) => {
                results.add_result(test_name, passed, None);
                if passed {
                    debug!("✓ Test {} passed", test_name);
                } else {
                    warn!("✗ Test {} failed", test_name);
                }
            }
            Err(e) => {
                error!("Test {} error: {}", test_name, e);
                results.add_result(test_name, false, Some(e.to_string()));
            }
        }
    }

    Ok(results)
}

/// Run a single security test case
async fn run_single_security_test(
    listener: &TcpListener,
    server_addr: std::net::SocketAddr,
    malicious_message: &str,
    expected_behavior: ExpectedBehavior,
) -> Result<bool> {
    // Start the mock server in the background
    let listener = Arc::new(Mutex::new(listener));
    let malicious_message = malicious_message.to_string();
    
    let server_task = {
        let listener = listener.clone();
        let malicious_message = malicious_message.clone();
        
        tokio::spawn(async move {
            let listener = listener.lock().await;
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    debug!("Server: Accepted connection, sending malicious message");
                    
                    // Send the malicious message
                    if let Err(e) = stream.write_all(malicious_message.as_bytes()).await {
                        error!("Server: Failed to send message: {}", e);
                        return;
                    }

                    // Wait a bit for client response
                    let mut buffer = [0u8; 1024];
                    match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
                        Ok(Ok(n)) => {
                            let response = String::from_utf8_lossy(&buffer[..n]);
                            debug!("Server: Received client response: {}", response.trim());
                        }
                        Ok(Err(e)) => debug!("Server: Client read error: {}", e),
                        Err(_) => debug!("Server: Client response timeout"),
                    }
                }
                Err(e) => error!("Server: Failed to accept connection: {}", e),
            }
        })
    };

    // Simulate client connection and message parsing
    let client_result = tokio::spawn(async move {
        // Connect to the test server
        let stream = match TcpStream::connect(server_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Client: Failed to connect: {}", e);
                return false;
            }
        };

        debug!("Client: Connected to test server");

        // Try to read and parse the malicious message
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        match tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                debug!("Client: Connection closed by server");
                expected_behavior == ExpectedBehavior::Disconnect
            }
            Ok(Ok(_)) => {
                debug!("Client: Received message: {}", line.trim());

                // Try to parse the message using the client's parser
                match line.parse::<IrcMessage>() {
                    Ok(msg) => {
                        debug!("Client: Successfully parsed message: {:?}", msg);
                        expected_behavior == ExpectedBehavior::Accept
                    }
                    Err(e) => {
                        debug!("Client: Failed to parse message: {}", e);
                        
                        // Check if it's a security violation
                        match e {
                            IronError::SecurityViolation(_) => {
                                expected_behavior == ExpectedBehavior::Reject
                            }
                            IronError::Parse(_) => {
                                expected_behavior == ExpectedBehavior::Reject
                            }
                            _ => false,
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("Client: Read error: {}", e);
                expected_behavior == ExpectedBehavior::Reject || expected_behavior == ExpectedBehavior::Disconnect
            }
            Err(_) => {
                debug!("Client: Read timeout");
                expected_behavior == ExpectedBehavior::Reject
            }
        }
    });

    // Wait for both tasks to complete
    let (server_result, client_result) = tokio::join!(server_task, client_result);

    match (server_result, client_result) {
        (Ok(_), Ok(test_passed)) => Ok(test_passed),
        (Err(e), _) => {
            error!("Server task failed: {}", e);
            Ok(false)
        }
        (_, Err(e)) => {
            error!("Client task failed: {}", e);
            Ok(false)
        }
    }
}

/// Test specific security vulnerabilities
#[tokio::test]
async fn test_buffer_overflow_protection() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that extremely large messages are rejected
    let huge_message = "A".repeat(100000);
    let result = huge_message.parse::<IrcMessage>();
    assert!(result.is_err(), "Huge message should be rejected");

    // Test that huge tags are rejected
    let huge_tags = format!("@{} PRIVMSG #test :hello", "tag=value;".repeat(10000));
    let result = huge_tags.parse::<IrcMessage>();
    assert!(result.is_err(), "Huge tags should be rejected");
}

#[tokio::test]
async fn test_injection_attacks() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test command injection in parameters
    let injection_attempt = "PRIVMSG #test :hello\r\nQUIT :injected command\r\n";
    let result = injection_attempt.parse::<IrcMessage>();
    assert!(result.is_err(), "Command injection should be rejected");

    // Test null byte injection
    let null_injection = "PRIVMSG #test :hello\0QUIT :injected";
    let result = null_injection.parse::<IrcMessage>();
    assert!(result.is_err(), "Null byte injection should be rejected");
}

#[tokio::test]
async fn test_protocol_confusion() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test HTTP request parsing
    let http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = http_request.parse::<IrcMessage>();
    assert!(result.is_err(), "HTTP request should be rejected");

    // Test SMTP command
    let smtp_command = "EHLO example.com\r\n";
    let result = smtp_command.parse::<IrcMessage>();
    assert!(result.is_err(), "SMTP command should be rejected");
}

#[tokio::test]
async fn test_malformed_data_handling() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test completely invalid data
    let invalid_data = "\xFF\xFE\xFD\xFC";
    let result = invalid_data.parse::<IrcMessage>();
    assert!(result.is_err(), "Invalid binary data should be rejected");

    // Test empty message
    let empty = "";
    let result = empty.parse::<IrcMessage>();
    assert!(result.is_err(), "Empty message should be rejected");

    // Test only whitespace
    let whitespace = "   \r\n";
    let result = whitespace.parse::<IrcMessage>();
    assert!(result.is_err(), "Whitespace-only message should be rejected");
}

#[tokio::test]
async fn test_dos_protection() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test rapid parsing of many messages (performance test)
    let start = std::time::Instant::now();
    
    for i in 0..1000 {
        let message = format!("PRIVMSG #test{} :Hello world {}", i, i);
        let result = message.parse::<IrcMessage>();
        assert!(result.is_ok(), "Valid message should parse successfully");
    }
    
    let duration = start.elapsed();
    info!("Parsed 1000 messages in {:?}", duration);
    
    // Should complete quickly (under 100ms for 1000 messages)
    assert!(duration < Duration::from_millis(100), 
        "Message parsing too slow: {:?}", duration);
}

/// Test that validates the comprehensive security measures
#[tokio::test]
async fn test_comprehensive_security_validation() {
    let _ = tracing_subscriber::fmt::try_init();

    info!("Running comprehensive security validation");

    // Test that all the expected security measures are in place
    let security_tests = vec![
        // Length limits
        ("Max message length", "A".repeat(600), false),
        ("Max command length", &format!("{} #test :hello", "A".repeat(50)), false),
        ("Max tag length", &format!("@{} PRIVMSG #test :hello", "tag=".repeat(3000)), false),
        ("Max parameter count", &format!("PRIVMSG {} :hello", 
            (0..20).map(|i| format!("#{}", i)).collect::<Vec<_>>().join(" ")), false),
        
        // Character validation
        ("Null bytes", "PRIVMSG #test :hello\0world", false),
        ("Carriage returns", "PRIVMSG #test :hello\rworld", false),
        ("Line feeds", "PRIVMSG #test :hello\nworld", false),
        ("Non-ASCII", "PRIVMSG #test :héllo", false),
        
        // Command validation
        ("Invalid command chars", "PRIV@MSG #test :hello", false),
        ("Empty command", " #test :hello", false),
        ("Numeric command wrong length", "1234 nick :hello", false),
        
        // Prefix validation
        ("Prefix with space", ":nick name!user@host PRIVMSG #test :hello", false),
        ("Oversized prefix", &format!(":{}!user@host PRIVMSG #test :hello", "A".repeat(300)), false),
        
        // Tag validation
        ("Invalid tag key", "@invalid@key=value PRIVMSG #test :hello", false),
        
        // Valid messages (should pass)
        ("Valid simple message", "PRIVMSG #test :Hello world", true),
        ("Valid with tags", "@time=2023-01-01T00:00:00.000Z PRIVMSG #test :Hello", true),
        ("Valid with prefix", ":nick!user@host PRIVMSG #test :Hello", true),
        ("Valid numeric", "001 nick :Welcome", true),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (test_name, message, should_pass) in security_tests {
        match message.parse::<IrcMessage>() {
            Ok(_) => {
                if should_pass {
                    passed += 1;
                    debug!("✓ {}: Message correctly accepted", test_name);
                } else {
                    failed += 1;
                    error!("✗ {}: Message should have been rejected but was accepted", test_name);
                }
            }
            Err(_) => {
                if !should_pass {
                    passed += 1;
                    debug!("✓ {}: Message correctly rejected", test_name);
                } else {
                    failed += 1;
                    error!("✗ {}: Message should have been accepted but was rejected", test_name);
                }
            }
        }
    }

    info!("Comprehensive security validation: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Security validation failed {} tests", failed);
}