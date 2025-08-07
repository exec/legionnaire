use ironchat::{
    config::{Config, SaslConfig},
    message::IrcMessage,
    capabilities::CapabilityHandler,
    auth::{SaslAuthenticator, SecureCredentials},
    error::IronError,
};
use tokio::time::Duration;
use tempfile::TempDir;
use std::fs;

// Integration test for full IRC message flow
#[tokio::test]
async fn test_complete_message_flow() {
    // Test message parsing -> processing -> formatting
    let test_messages = vec![
        "PING :server.example.com",
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello",
        ":nick!user@host JOIN #channel",
        "001 testnick :Welcome to IRC",
        "353 testnick = #channel :nick1 nick2 nick3",
        "366 testnick #channel :End of NAMES list",
    ];
    
    for msg_str in test_messages {
        // Parse message
        let parsed = msg_str.parse::<IrcMessage>().unwrap();
        
        // Verify parsing worked correctly
        assert!(!parsed.command.is_empty());
        
        // Format message back to string
        let formatted = parsed.to_string();
        
        // Parse the formatted message again (round-trip test)
        let reparsed = formatted.parse::<IrcMessage>().unwrap();
        
        // Verify round-trip consistency
        assert_eq!(parsed.command, reparsed.command);
        assert_eq!(parsed.params, reparsed.params);
        assert_eq!(parsed.prefix, reparsed.prefix);
        assert_eq!(parsed.tags.len(), reparsed.tags.len());
    }
}

// Integration test for capability negotiation flow
#[tokio::test]
async fn test_capability_negotiation_flow() {
    let mut handler = CapabilityHandler::new();
    
    // 1. Server sends CAP LS (multiline)
    let params1 = vec!["*".to_string(), "LS".to_string(), 
                      "sasl=PLAIN,EXTERNAL message-tags server-time".to_string()];
    let complete1 = handler.handle_cap_ls(&params1).unwrap();
    assert!(!complete1);
    
    let params2 = vec!["testnick".to_string(), "LS".to_string(), 
                      "batch cap-notify account-tag sts=duration=300".to_string()];
    let complete2 = handler.handle_cap_ls(&params2).unwrap();
    assert!(complete2);
    
    // 2. Client determines which capabilities to request
    let caps_to_request = handler.get_capabilities_to_request();
    assert!(!caps_to_request.is_empty());
    assert!(caps_to_request.contains(&"sasl".to_string()));
    assert!(caps_to_request.contains(&"message-tags".to_string()));
    
    // 3. Server acknowledges most capabilities
    let acknowledged = vec!["sasl".to_string(), "message-tags".to_string(), "server-time".to_string()];
    handler.handle_cap_ack(&acknowledged).unwrap();
    
    // 4. Server rejects some capabilities
    let rejected = vec!["batch".to_string()];
    handler.handle_cap_nak(&rejected).unwrap();
    
    // 5. Verify final state
    assert!(handler.is_capability_enabled("sasl"));
    assert!(handler.is_capability_enabled("message-tags"));
    assert!(handler.is_capability_enabled("server-time"));
    assert!(!handler.is_capability_enabled("batch"));
    
    // 6. Complete negotiation
    handler.set_negotiation_complete();
    assert!(handler.is_negotiation_complete());
    
    // 7. Test SASL mechanism extraction
    let mechanisms = handler.get_sasl_mechanisms();
    assert_eq!(mechanisms, vec!["PLAIN", "EXTERNAL"]);
}

// Integration test for SASL authentication flow
#[tokio::test]
async fn test_sasl_authentication_flow() {
    let mut authenticator = SaslAuthenticator::new();
    
    // Add multiple authentication methods
    authenticator.add_plain_auth("testuser".to_string(), 
                                secrecy::SecretString::new("testpass".to_string()));
    authenticator.add_external_auth(None);
    
    // Test mechanism selection priority (EXTERNAL > PLAIN)
    let server_mechanisms = vec!["PLAIN".to_string(), "EXTERNAL".to_string()];
    let selected = authenticator.select_mechanism(&server_mechanisms);
    
    assert!(selected.is_some());
    assert!(matches!(selected.unwrap(), 
                    ironchat::auth::SaslMechanism::External { .. }));
    
    // Test with only PLAIN available
    let plain_only = vec!["PLAIN".to_string()];
    let selected_plain = authenticator.select_mechanism(&plain_only);
    
    assert!(selected_plain.is_some());
    assert!(matches!(selected_plain.unwrap(), 
                    ironchat::auth::SaslMechanism::Plain { .. }));
    
    // Test with no supported mechanisms
    let unsupported = vec!["KERBEROS".to_string()];
    let selected_none = authenticator.select_mechanism(&unsupported);
    assert!(selected_none.is_none());
}

// Integration test for configuration system
#[tokio::test]
async fn test_configuration_system() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("test_config.toml");
    
    // Create a comprehensive configuration
    let toml_content = r##"
default_server = "TestServer"

[[servers]]
name = "TestServer"
host = "irc.test.com"
port = 6697
tls = true
verify_certificates = true
channels = ["#rust", "#programming"]

[servers.sasl]
mechanism = "Plain"
username = "testuser"
password = "testpass"

[user]
nickname = "testnick"
username = "testuser"
realname = "Test User"

[keybindings]
quit = "Ctrl+q"
toggle_help = "F1"
next_tab = "F2"
prev_tab = "F3"
"##;
    
    // Save configuration to file
    fs::write(&config_path, toml_content).unwrap();
    
    // Load and parse configuration
    let config_content = fs::read_to_string(&config_path).unwrap();
    let config: Config = toml::from_str(&config_content).unwrap();
    
    // Verify configuration structure
    assert_eq!(config.default_server, Some("TestServer".to_string()));
    assert_eq!(config.servers.len(), 1);
    
    let server = &config.servers[0];
    assert_eq!(server.name, "TestServer");
    assert_eq!(server.host, "irc.test.com");
    assert_eq!(server.port, 6697);
    assert!(server.tls);
    assert!(server.verify_certificates);
    assert_eq!(server.channels, vec!["#rust", "#programming"]);
    
    // Verify SASL configuration
    match &server.sasl {
        Some(SaslConfig::Plain { username, password }) => {
            assert_eq!(username, "testuser");
            assert_eq!(password, "testpass");
        }
        _ => panic!("Expected Plain SASL config"),
    }
    
    // Verify user configuration
    assert_eq!(config.user.nickname, "testnick");
    assert_eq!(config.user.username, Some("testuser".to_string()));
    assert_eq!(config.user.realname, Some("Test User".to_string()));
    
    // Verify keybindings
    assert_eq!(config.keybindings.quit, "Ctrl+q");
    assert_eq!(config.keybindings.toggle_help, "F1");
    
    // Test server selection
    let selected_server = config.get_server(None);
    assert!(selected_server.is_some());
    assert_eq!(selected_server.unwrap().name, "TestServer");
    
    // Test key parsing
    let parsed_quit = config.keybindings.parse_key(&config.keybindings.quit);
    assert!(parsed_quit.is_some());
    
    let parsed_help = config.keybindings.parse_key(&config.keybindings.toggle_help);
    assert!(parsed_help.is_some());
}

// Integration test for error handling across modules
#[tokio::test]
async fn test_error_handling_integration() {
    // Test error propagation through different layers
    
    // 1. Message parsing errors
    let invalid_messages = vec![
        "", // Empty
        "INVALID_COMMAND_THAT_IS_TOO_LONG_TO_BE_VALID #channel :test",
        "@invalid tag=value PRIVMSG #channel :test",
        "PRIVMSG #channel\0 :test", // Null byte
    ];
    
    for invalid_msg in invalid_messages {
        let result = invalid_msg.parse::<IrcMessage>();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        match error {
            IronError::Parse(_) | IronError::SecurityViolation(_) => {
                // Expected error types
                let error_msg = error.to_string();
                assert!(!error_msg.is_empty());
            }
            _ => panic!("Unexpected error type: {:?}", error),
        }
    }
    
    // 2. Configuration errors
    let invalid_toml = r#"
[user
nickname = "testnick"
# Missing closing bracket
"#;
    
    let config_result: std::result::Result<Config, _> = toml::from_str(invalid_toml);
    assert!(config_result.is_err());
    
    // 3. Authentication errors
    let creds_result = SecureCredentials::from_env("NONEXISTENT_USER", "NONEXISTENT_PASS");
    assert!(matches!(creds_result, Err(IronError::Auth(_))));
    
    // 4. Capability handling errors
    let mut handler = CapabilityHandler::new();
    let invalid_params = vec!["nick".to_string()]; // Too few parameters
    let cap_result = handler.handle_cap_ls(&invalid_params);
    assert!(matches!(cap_result, Err(IronError::Parse(_))));
}

// Integration test for security validation across modules
#[tokio::test]
async fn test_security_validation_integration() {
    // Test that security checks are applied consistently
    
    // 1. Message security validation
    let security_tests = vec!(
        ("Command too long", "A".repeat(100) + " #channel :test"),
        ("Parameter too long", format!("PRIVMSG {} :test", "a".repeat(600))),
        ("Too many parameters", format!("COMMAND {}", (0..20).map(|i| format!("param{}", i)).collect::<Vec<_>>().join(" "))),
        ("Null byte in message", "PRIVMSG #channel\0 :test".to_string()),
        ("Non-ASCII in message", "PRIVMSG #channel :Hello 世界".to_string()),
    );
    
    for (test_name, test_message) in security_tests {
        let result = test_message.parse::<IrcMessage>();
        assert!(result.is_err(), "Security test failed: {}", test_name);
        
        if let Err(error) = result {
            match error {
                IronError::SecurityViolation(_) => {
                    // Expected
                    println!("✓ Security test passed: {}", test_name);
                }
                _ => panic!("Expected SecurityViolation for: {}", test_name),
            }
        }
    }
    
    // 2. Capability name validation
    let mut cap_handler = CapabilityHandler::new();
    let malicious_caps = vec![
        "invalid name=value", // Space in name
        "../../etc/passwd=value", // Path traversal attempt
        "invalid@name=value", // Invalid character
    ];
    
    for malicious_cap in malicious_caps {
        let params = vec!["nick".to_string(), "LS".to_string(), malicious_cap.to_string()];
        let result = cap_handler.handle_cap_ls(&params);
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }
    
    // 3. Authentication security checks
    let long_username = "a".repeat(300);
    let long_password = "b".repeat(1500);
    
    std::env::set_var("LONG_USERNAME", &long_username);
    std::env::set_var("LONG_PASSWORD", &long_password);
    
    let creds_result = SecureCredentials::from_env("LONG_USERNAME", "LONG_PASSWORD");
    assert!(matches!(creds_result, Err(IronError::Auth(_))));
    
    std::env::remove_var("LONG_USERNAME");
    std::env::remove_var("LONG_PASSWORD");
}

// Integration test for real-world IRC scenario simulation
#[tokio::test]
async fn test_irc_session_simulation() {
    // Simulate a complete IRC session flow
    let mut cap_handler = CapabilityHandler::new();
    let mut sasl_auth = SaslAuthenticator::new();
    
    // 1. Capability negotiation
    let cap_ls_params = vec!["*".to_string(), "LS".to_string(), 
                            "sasl=PLAIN,EXTERNAL message-tags server-time account-tag".to_string()];
    cap_handler.handle_cap_ls(&cap_ls_params).unwrap();
    
    let caps_to_request = cap_handler.get_capabilities_to_request();
    cap_handler.handle_cap_ack(&caps_to_request).unwrap();
    
    // 2. SASL Authentication setup
    sasl_auth.add_plain_auth("testuser".to_string(), 
                            secrecy::SecretString::new("testpass".to_string()));
    
    let mechanisms = cap_handler.get_sasl_mechanisms();
    let selected_mechanism = sasl_auth.select_mechanism(&mechanisms);
    assert!(selected_mechanism.is_some());
    
    // 3. Connection messages simulation
    let connection_messages = vec![
        "001 testnick :Welcome to the IRC Network",
        "002 testnick :Your host is irc.test.com",
        "003 testnick :This server was created Mon Jan 1 2023",
        "004 testnick irc.test.com ircd-test ABC abc",
        "005 testnick CHANTYPES=# PREFIX=(ov)@+ :are supported",
        "251 testnick :There are 100 users and 0 services on 1 servers",
        "375 testnick :- irc.test.com Message of the Day",
        "372 testnick :- Welcome to our IRC server!",
        "376 testnick :End of MOTD command",
    ];
    
    let mut parsed_messages = Vec::new();
    for msg_str in connection_messages {
        let parsed = msg_str.parse::<IrcMessage>().unwrap();
        parsed_messages.push(parsed);
    }
    
    // Verify all messages parsed successfully
    assert_eq!(parsed_messages.len(), 9);
    
    // 4. Channel operations simulation
    let channel_messages = vec![
        "JOIN #rust",
        "333 testnick #rust topic-setter!user@host 1672531200",
        "353 testnick = #rust :testnick @operator +voice regular",
        "366 testnick #rust :End of NAMES list",
        "PRIVMSG #rust :Hello everyone!",
        "@time=2023-01-01T12:00:00.000Z :other!user@host PRIVMSG #rust :Hi testnick!",
        "MODE #rust +o testnick",
        "PART #rust :Goodbye!",
    ];
    
    for msg_str in channel_messages {
        let parsed = msg_str.parse::<IrcMessage>().unwrap();
        
        // Verify message structure based on command
        match parsed.command.as_str() {
            "JOIN" | "PART" => {
                assert!(!parsed.params.is_empty());
                assert!(parsed.params[0].starts_with('#'));
            }
            "PRIVMSG" => {
                assert_eq!(parsed.params.len(), 2);
                assert!(parsed.params[0].starts_with('#'));
            }
            "MODE" => {
                assert!(parsed.params.len() >= 2);
            }
            numeric if numeric.chars().all(|c| c.is_ascii_digit()) => {
                // Numeric replies should have at least nick parameter
                assert!(!parsed.params.is_empty());
            }
            _ => {} // Other commands are fine as-is
        }
    }
    
    // 5. Complete negotiation
    cap_handler.set_negotiation_complete();
    assert!(cap_handler.is_negotiation_complete());
}

// Integration test for error recovery scenarios
#[tokio::test]
async fn test_error_recovery_scenarios() {
    // Test various error conditions and recovery strategies
    
    // 1. Capability negotiation with partial failures
    let mut handler = CapabilityHandler::new();
    
    // Add capabilities
    let params = vec!["nick".to_string(), "LS".to_string(), 
                     "sasl=PLAIN message-tags server-time batch unknown-cap".to_string()];
    handler.handle_cap_ls(&params).unwrap();
    
    let caps_to_request = handler.get_capabilities_to_request();
    
    // Server rejects some capabilities
    let rejected = vec!["unknown-cap".to_string(), "batch".to_string()];
    handler.handle_cap_nak(&rejected).unwrap();
    
    // Server accepts others
    let accepted: Vec<String> = caps_to_request.iter()
        .filter(|cap| !rejected.contains(cap))
        .cloned()
        .collect();
    handler.handle_cap_ack(&accepted).unwrap();
    
    // Verify partial success
    assert!(!handler.is_capability_enabled("unknown-cap"));
    assert!(!handler.is_capability_enabled("batch"));
    
    // At least some capabilities should be enabled
    let enabled_count = vec!["sasl", "message-tags", "server-time"]
        .iter()
        .filter(|cap| handler.is_capability_enabled(cap))
        .count();
    assert!(enabled_count > 0);
    
    // 2. Message parsing with error recovery
    let mixed_messages = vec![
        "PING :server.test.com", // Valid
        "INVALID_COMMAND_TOO_LONG_SERIOUSLY_WAY_TOO_LONG #channel :test", // Invalid
        "PRIVMSG #channel :Hello", // Valid
        "", // Invalid
        "001 nick :Welcome", // Valid
    ];
    
    let mut valid_count = 0;
    let mut error_count = 0;
    
    for msg_str in mixed_messages {
        match msg_str.parse::<IrcMessage>() {
            Ok(_) => valid_count += 1,
            Err(_) => error_count += 1,
        }
    }
    
    assert_eq!(valid_count, 3);
    assert_eq!(error_count, 2);
    
    // 3. Configuration error recovery
    let partial_config = r#"
[user]
nickname = "testnick"
# username intentionally missing

[[servers]]
name = "TestServer"
host = "irc.test.com"
# Other fields will use defaults
"#;
    
    let config: Config = toml::from_str(partial_config).unwrap();
    
    // Verify defaults are applied
    assert_eq!(config.user.nickname, "testnick");
    assert_eq!(config.user.username, None); // Should be None when not specified
    assert_eq!(config.servers[0].port, 6697); // Default port
    assert!(config.servers[0].tls); // Default TLS
}

// Property-based integration test
#[tokio::test]
async fn test_property_based_integration() {
    // Test that certain properties hold across the system
    
    // Property 1: All parsed messages can be formatted and reparsed
    let test_messages = vec![
        "PING :server",
        "PRIVMSG #channel :Hello",
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello",
        ":nick!user@host JOIN #channel",
        "001 nick :Welcome",
        "353 nick = #channel :nick1 nick2",
        "366 nick #channel :End of NAMES",
    ];
    
    for original in test_messages {
        let parsed = original.parse::<IrcMessage>().unwrap();
        let formatted = parsed.to_string();
        let reparsed = formatted.parse::<IrcMessage>().unwrap();
        
        // Property: command should be preserved
        assert_eq!(parsed.command, reparsed.command);
        
        // Property: parameter count should be preserved
        assert_eq!(parsed.params.len(), reparsed.params.len());
        
        // Property: prefix presence should be preserved
        assert_eq!(parsed.prefix.is_some(), reparsed.prefix.is_some());
        
        // Property: tag count should be preserved
        assert_eq!(parsed.tags.len(), reparsed.tags.len());
    }
    
    // Property 2: Error types should be consistent
    let long_input = "A".repeat(100);
    let invalid_inputs = vec![
        "",
        long_input.as_str(),
        "PRIVMSG #channel\0 :test",
        "@invalid tag PRIVMSG #channel :test",
    ];
    
    for invalid in invalid_inputs {
        let result = invalid.parse::<IrcMessage>();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        // Property: Security violations and parse errors should have meaningful messages
        let error_msg = error.to_string();
        assert!(!error_msg.is_empty());
        assert!(error_msg.len() > 10); // Should be descriptive
    }
    
    // Property 3: Configuration round-trips should preserve essential data
    let config = Config::default();
    let serialized = toml::to_string_pretty(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();
    
    // Property: Server count should be preserved
    assert_eq!(config.servers.len(), deserialized.servers.len());
    
    // Property: Default server should be preserved
    assert_eq!(config.default_server, deserialized.default_server);
    
    // Property: User nickname should be preserved
    assert_eq!(config.user.nickname, deserialized.user.nickname);
}

// Integration test for IRCv3 MessageReply and MessageReaction functionality
#[cfg(feature = "bleeding-edge")]
#[tokio::test]
async fn test_ircv3_reply_react_integration() {
    use iron_protocol::{MessageReply, MessageReaction, ReactionAction};
    
    // Test 1: MessageReply creation and parsing
    let reply = MessageReply::new(
        "#rust".to_string(),
        "msg-12345".to_string(), 
        "@alice Thanks for the help!".to_string()
    );
    
    let reply_msg = reply.to_message();
    
    // Verify reply message structure
    assert_eq!(reply_msg.command, "PRIVMSG");
    assert_eq!(reply_msg.params, vec!["#rust", "@alice Thanks for the help!"]);
    assert!(reply_msg.has_tag("+draft/reply"));
    assert_eq!(reply_msg.get_tag("+draft/reply"), Some(&Some("msg-12345".to_string())));
    
    // Test round-trip parsing
    let reply_str = reply_msg.to_string();
    let parsed_msg = reply_str.parse::<iron_protocol::IrcMessage>().unwrap();
    
    let parsed_reply = MessageReply::from_message(&parsed_msg).unwrap();
    assert_eq!(parsed_reply.target, "#rust");
    assert_eq!(parsed_reply.msgid, "msg-12345");
    assert_eq!(parsed_reply.reply_text, "@alice Thanks for the help!");
    
    // Test 2: MessageReaction creation and parsing
    let reaction = MessageReaction::new(
        "#rust".to_string(),
        "msg-12345".to_string(),
        "👍".to_string(),
        ReactionAction::Add
    );
    
    let reaction_msg = reaction.to_message();
    
    // Verify reaction message structure
    assert_eq!(reaction_msg.command, "TAGMSG");
    assert_eq!(reaction_msg.params, vec!["#rust"]);
    assert!(reaction_msg.has_tag("+draft/react"));
    assert!(reaction_msg.has_tag("+draft/reply"));
    assert_eq!(reaction_msg.get_tag("+draft/react"), Some(&Some("+👍".to_string())));
    assert_eq!(reaction_msg.get_tag("+draft/reply"), Some(&Some("msg-12345".to_string())));
    
    // Test round-trip parsing
    let reaction_str = reaction_msg.to_string();
    let parsed_reaction_msg = reaction_str.parse::<iron_protocol::IrcMessage>().unwrap();
    
    let parsed_reaction = MessageReaction::from_message(&parsed_reaction_msg).unwrap();
    assert_eq!(parsed_reaction.target, "#rust");
    assert_eq!(parsed_reaction.msgid, "msg-12345");
    assert_eq!(parsed_reaction.reaction, "👍");
    assert_eq!(parsed_reaction.action, ReactionAction::Add);
    
    // Test 3: Complex IRCv3 message parsing with multiple tags
    let complex_msg_str = r#"@msgid=abc123;time=2024-01-01T12:00:00.000Z;+draft/reply=original456 PRIVMSG #rust :@bob This is a threaded reply with timestamp"#;
    let complex_msg = complex_msg_str.parse::<iron_protocol::IrcMessage>().unwrap();
    
    // Verify all tags are parsed correctly
    assert!(complex_msg.has_tag("msgid"));
    assert!(complex_msg.has_tag("time"));
    assert!(complex_msg.has_tag("+draft/reply"));
    
    assert_eq!(complex_msg.get_msgid(), Some("abc123"));
    assert_eq!(complex_msg.get_tag("time"), Some(&Some("2024-01-01T12:00:00.000Z".to_string())));
    assert_eq!(complex_msg.get_tag("+draft/reply"), Some(&Some("original456".to_string())));
    
    // Test that it can be parsed as a MessageReply
    let complex_reply = MessageReply::from_message(&complex_msg).unwrap();
    assert_eq!(complex_reply.target, "#rust");
    assert_eq!(complex_reply.msgid, "original456");
    assert_eq!(complex_reply.reply_text, "@bob This is a threaded reply with timestamp");
    
    // Test 4: Error handling for invalid IRCv3 messages
    let invalid_messages = vec![
        "@+draft/reply= PRIVMSG #rust :Empty reply tag",
        "TAGMSG #rust", // No reaction tag
        "@+draft/react=invalid TAGMSG #rust", // Invalid reaction format
    ];
    
    for invalid_msg in invalid_messages {
        let parsed = invalid_msg.parse::<iron_protocol::IrcMessage>().unwrap();
        
        // Should fail to parse as reply/reaction due to invalid format
        if parsed.has_tag("+draft/reply") {
            assert!(MessageReply::from_message(&parsed).is_err());
        }
        if parsed.has_tag("+draft/react") {
            assert!(MessageReaction::from_message(&parsed).is_err());
        }
    }
    
    println!("✓ IRCv3 reply/reaction functionality working correctly");
}

// Integration test for IRCv3 tag parsing edge cases
#[cfg(feature = "bleeding-edge")]
#[tokio::test]
async fn test_ircv3_tag_parsing_edge_cases() {
    // Test various IRCv3 tag formats and edge cases
    let test_cases = vec![
        // Basic tags
        ("@simple=value PRIVMSG #test :msg", vec![("simple", Some("value"))]),
        
        // Tags with no value
        ("@flag PRIVMSG #test :msg", vec![("flag", None)]),
        
        // Multiple tags
        ("@tag1=val1;tag2=val2 PRIVMSG #test :msg", vec![("tag1", Some("val1")), ("tag2", Some("val2"))]),
        
        // Draft capabilities
        ("@+draft/reply=msg123;+draft/react=+👍 TAGMSG #test", vec![("+draft/reply", Some("msg123")), ("+draft/react", Some("+👍"))]),
        
        // Mixed standard and draft tags
        ("@msgid=abc;+draft/reply=def;time=2024-01-01T00:00:00.000Z PRIVMSG #test :msg", 
         vec![("msgid", Some("abc")), ("+draft/reply", Some("def")), ("time", Some("2024-01-01T00:00:00.000Z"))]),
        
        // Empty tag value
        ("@key= PRIVMSG #test :msg", vec![("key", Some(""))]),
    ];
    
    for (msg_str, expected_tags) in test_cases {
        let parsed = msg_str.parse::<iron_protocol::IrcMessage>().unwrap();
        
        // Check that all expected tags are present
        for (key, expected_value) in expected_tags {
            assert!(parsed.has_tag(key), "Missing tag: {}", key);
            let actual_value = parsed.get_tag(key).unwrap();
            match (expected_value, actual_value) {
                (Some(exp), Some(act)) => assert_eq!(exp, act, "Tag value mismatch for {}", key),
                (None, None) => {}, // Both None, good
                _ => panic!("Tag value presence mismatch for {}: expected {:?}, got {:?}", key, expected_value, actual_value),
            }
        }
    }
    
    println!("✓ IRCv3 tag parsing edge cases handled correctly");
}

// Performance integration test
#[tokio::test]
async fn test_performance_integration() {
    // Test that the system can handle reasonable loads
    
    let start = std::time::Instant::now();
    
    // Parse 1000 messages
    for i in 0..1000 {
        let msg_str = format!("PRIVMSG #channel{} :Message number {}", i % 10, i);
        let parsed = msg_str.parse::<IrcMessage>().unwrap();
        let _formatted = parsed.to_string();
    }
    
    let duration = start.elapsed();
    
    // Should complete within reasonable time (adjust as needed)
    assert!(duration < Duration::from_millis(100), 
           "Performance test took too long: {:?}", duration);
    
    println!("✓ Parsed and formatted 1000 messages in {:?}", duration);
}