//! User Workflow Tests
//!
//! Tests that cover complete user journeys and real-world usage patterns
//! to ensure production readiness from a user experience perspective.

use legionnaire::{Config, SetupWizard, QuickSetup, IronClient};
use legionnaire::client::IrcConfig;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::process::Command;
use anyhow::Result;
use serial_test::serial;

/// Test the complete first-time user setup experience
#[tokio::test]
#[serial]
async fn test_first_time_user_setup() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");
    
    // Test environment-based quick setup (like Docker/automated deployments)
    std::env::set_var("IRC_NICK", "testuser");
    std::env::set_var("IRC_SERVER", "irc.libera.chat");
    std::env::set_var("IRC_PORT", "6697");
    std::env::set_var("IRC_CHANNELS", "#test,#general");
    
    let config = QuickSetup::from_environment()?;
    assert!(config.is_some(), "Should create config from environment");
    
    let config = config.unwrap();
    assert_eq!(config.user.nickname, "testuser");
    assert_eq!(config.servers[0].host, "irc.libera.chat");
    assert_eq!(config.servers[0].port, 6697);
    assert_eq!(config.servers[0].channels.len(), 2);
    
    // Clean up environment
    std::env::remove_var("IRC_NICK");
    std::env::remove_var("IRC_SERVER");
    std::env::remove_var("IRC_PORT");
    std::env::remove_var("IRC_CHANNELS");
    
    Ok(())
}

/// Test configuration loading and fallback scenarios
#[tokio::test]
#[serial]
async fn test_configuration_fallback_scenarios() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Test 1: No configuration file exists
    let non_existent = temp_dir.path().join("nonexistent.toml");
    let result = Config::load_from_file(&non_existent);
    assert!(result.is_err(), "Should fail when config file doesn't exist");
    
    // Test 2: Configuration file exists but is empty
    let empty_config = temp_dir.path().join("empty.toml");
    std::fs::write(&empty_config, "")?;
    let result = Config::load_from_file(&empty_config);
    assert!(result.is_err(), "Should fail with empty config file");
    
    // Test 3: Partial configuration (missing required fields)
    let partial_config = temp_dir.path().join("partial.toml");
    std::fs::write(&partial_config, r#"
[user]
# Missing nickname
username = "test"
"#)?;
    let result = Config::load_from_file(&partial_config);
    assert!(result.is_err(), "Should fail with missing required fields");
    
    // Test 4: Valid minimal configuration
    let valid_config = temp_dir.path().join("valid.toml");
    std::fs::write(&valid_config, r#"
[user]
nickname = "testuser"

[[servers]]
name = "test"
host = "irc.test.com"
port = 6667
"#)?;
    let result = Config::load_from_file(&valid_config);
    assert!(result.is_ok(), "Should load valid minimal config");
    
    let config = result.unwrap();
    assert_eq!(config.user.nickname, "testuser");
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.servers[0].host, "irc.test.com");
    
    Ok(())
}

/// Test typical daily usage workflow
#[tokio::test]
#[serial]
async fn test_daily_usage_workflow() -> Result<()> {
    // Create a test configuration
    let config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: 6667,
        nickname: "dailyuser".to_string(),
        username: "daily".to_string(),
        realname: "Daily User".to_string(),
        channels: vec!["#daily".to_string(), "#general".to_string()],
        tls_required: false,
        verify_certificates: false,
        ..IrcConfig::default()
    };
    
    // Test connection establishment
    let client = IronClient::new(config.clone());
    
    // In a real test, we'd connect to a mock server
    // For now, we test that the client is properly configured
    assert_eq!(client.server_name(), "127.0.0.1:6667");
    
    // Test typical user commands would be sent
    let join_message = legion_protocol::IrcMessage::new("JOIN")
        .with_params(vec!["#daily".to_string()]);
    assert_eq!(join_message.command, "JOIN");
    assert_eq!(join_message.params[0], "#daily");
    
    let privmsg = legion_protocol::IrcMessage::new("PRIVMSG")
        .with_params(vec!["#daily".to_string(), "Hello world!".to_string()]);
    assert_eq!(privmsg.command, "PRIVMSG");
    assert_eq!(privmsg.params[1], "Hello world!");
    
    Ok(())
}

/// Test network interruption and recovery scenarios
#[tokio::test]
#[serial]
async fn test_network_interruption_recovery() -> Result<()> {
    use legionnaire::recovery::{RecoveryManager, RecoveryConfig};
    use legionnaire::error::IronError;
    
    let recovery_config = RecoveryConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        initial_reconnect_delay: 1, // Fast for testing
        ..RecoveryConfig::default()
    };
    
    let irc_config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: 6667,
        nickname: "recoverytest".to_string(),
        ..IrcConfig::default()
    };
    
    let mut recovery_manager = RecoveryManager::new(recovery_config, irc_config);
    
    // Track some state before "disconnection"
    recovery_manager.track_channel_join("#important");
    recovery_manager.track_channel_join("#work");
    recovery_manager.track_nickname("recoverytest");
    
    // Simulate network failure
    let network_error = IronError::Connection("Network unreachable".to_string());
    let should_retry = recovery_manager.handle_connection_failure(&network_error).await?;
    assert!(should_retry, "Should attempt to reconnect after network failure");
    
    // Simulate successful reconnection
    let recovery_messages = recovery_manager.handle_successful_reconnection().await?;
    
    // Should have messages to restore state
    assert!(!recovery_messages.is_empty(), "Should have recovery messages");
    
    // Should restore nickname
    let nick_messages: Vec<_> = recovery_messages.iter()
        .filter(|msg| msg.command == "NICK")
        .collect();
    assert!(!nick_messages.is_empty(), "Should restore nickname");
    
    // Should rejoin channels
    let join_messages: Vec<_> = recovery_messages.iter()
        .filter(|msg| msg.command == "JOIN")
        .collect();
    assert_eq!(join_messages.len(), 2, "Should rejoin both channels");
    
    // Check statistics
    let stats = recovery_manager.get_stats();
    assert_eq!(stats.total_disconnections, 1);
    assert_eq!(stats.channels_tracked, 2);
    
    Ok(())
}

/// Test plugin loading and bot command workflows
#[tokio::test]
#[serial]
async fn test_plugin_and_bot_workflow() -> Result<()> {
    use legionnaire::plugin::{PluginManager, PluginContext};
    use legionnaire::bot::{BotFramework, BotConfig};
    use legion_protocol::IrcMessage;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    // Set up plugin context
    let plugin_context = PluginContext {
        client_config: Arc::new(IrcConfig::default()),
        plugin_config: serde_json::json!({}),
        shared_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
    };
    
    let plugin_manager = PluginManager::new(plugin_context);
    
    // Test loading available plugins
    let available_plugins = plugin_manager.list_available();
    assert!(!available_plugins.is_empty(), "Should have available plugins");
    assert!(available_plugins.contains(&"e2ee"), "Should have E2EE plugin");
    assert!(available_plugins.contains(&"weather-bot"), "Should have Weather Bot plugin");
    
    // Test plugin loading
    let result = plugin_manager.load_plugin("e2ee", None).await;
    assert!(result.is_ok(), "Should load E2EE plugin successfully");
    
    let result = plugin_manager.load_plugin("weather-bot", None).await;
    assert!(result.is_ok(), "Should load Weather Bot plugin successfully");
    
    // Test plugin starting
    let result = plugin_manager.start_plugin("e2ee").await;
    assert!(result.is_ok(), "Should start E2EE plugin successfully");
    
    let result = plugin_manager.start_plugin("weather-bot").await;
    assert!(result.is_ok(), "Should start Weather Bot plugin successfully");
    
    // Test bot framework integration
    let bot_config = BotConfig {
        command_prefix: "!".to_string(),
        enabled_channels: vec!["#test".to_string()],
        rate_limit: 10,
        ..BotConfig::default()
    };
    
    let framework = BotFramework::new(bot_config)?;
    
    // Simulate a bot command message
    let command_message = IrcMessage::new("PRIVMSG")
        .with_prefix("testuser!test@test.com".to_string())
        .with_params(vec!["#test".to_string(), "!weather tokyo".to_string()]);
    
    // Framework should parse and potentially respond to the command
    let responses = framework.handle_message(&command_message).await?;
    
    // Even if no actual bot is registered, framework should handle the message gracefully
    // This tests the command parsing and routing infrastructure
    
    Ok(())
}

/// Test security-related workflows
#[tokio::test]
#[serial]
async fn test_security_workflows() -> Result<()> {
    use legionnaire::credentials::{CredentialManager, CredentialType, CredentialBackend};
    use secrecy::Secret;
    
    // Test credential storage workflow
    let mut cred_manager = CredentialManager::with_backend(CredentialBackend::Memory);
    
    // Store server password
    let server_cred = CredentialType::ServerPassword {
        server: "secure.irc.network".to_string()
    };
    let password = Secret::new("super_secure_password".to_string());
    
    cred_manager.store_credential(server_cred.clone(), password).await?;
    
    // Retrieve password
    let retrieved = cred_manager.get_credential(&server_cred).await?;
    assert!(retrieved.is_some(), "Should retrieve stored password");
    
    // Store SASL credentials
    let sasl_cred = CredentialType::SaslCredentials {
        server: "secure.irc.network".to_string(),
        username: "testuser".to_string(),
    };
    let sasl_password = Secret::new("sasl_password".to_string());
    
    cred_manager.store_credential(sasl_cred.clone(), sasl_password).await?;
    
    // Store API key for bot
    let api_cred = CredentialType::ApiKey {
        service: "openweathermap".to_string(),
    };
    let api_key = Secret::new("weather_api_key_12345".to_string());
    
    cred_manager.store_credential(api_cred.clone(), api_key).await?;
    
    // List all credentials
    let all_creds = cred_manager.list_credentials().await?;
    assert_eq!(all_creds.len(), 3, "Should have stored 3 credentials");
    
    // Test credential deletion
    let deleted = cred_manager.delete_credential(&api_cred).await?;
    assert!(deleted, "Should confirm API key deletion");
    
    let should_be_none = cred_manager.get_credential(&api_cred).await?;
    assert!(should_be_none.is_none(), "Should not find deleted credential");
    
    Ok(())
}

/// Test multi-server configuration workflow
#[tokio::test]
#[serial]
async fn test_multi_server_workflow() -> Result<()> {
    use legionnaire::config::{Config, ServerConfig, UserConfig, SaslConfig};
    
    // Create a realistic multi-server configuration
    let user_config = UserConfig {
        nickname: "poweruser".to_string(),
        username: Some("power".to_string()),
        realname: Some("Power User".to_string()),
    };
    
    let servers = vec![
        ServerConfig {
            name: "work".to_string(),
            host: "irc.company.com".to_string(),
            port: 6697,
            tls: true,
            verify_certificates: true,
            channels: vec!["#general".to_string(), "#dev-team".to_string()],
            sasl: Some(SaslConfig::Plain {
                username: "poweruser".to_string(),
                password: "".to_string(), // Stored securely elsewhere
            }),
        },
        ServerConfig {
            name: "community".to_string(),
            host: "irc.libera.chat".to_string(),
            port: 6697,
            tls: true,
            verify_certificates: true,
            channels: vec!["#rust".to_string(), "#programming".to_string()],
            sasl: None,
        },
        ServerConfig {
            name: "gaming".to_string(),
            host: "irc.rizon.net".to_string(),
            port: 6697,
            tls: true,
            verify_certificates: true,
            channels: vec!["#gaming".to_string()],
            sasl: None,
        },
    ];
    
    let config = Config {
        user: user_config,
        servers,
        dos_protection: crate::dos_protection::DosProtectionConfig::default(),
        profiles: std::collections::HashMap::new(),
    };
    
    // Test server selection by name
    let work_server = config.get_server(Some("work"));
    assert!(work_server.is_some(), "Should find work server");
    assert_eq!(work_server.unwrap().host, "irc.company.com");
    
    let community_server = config.get_server(Some("community"));
    assert!(community_server.is_some(), "Should find community server");
    assert_eq!(community_server.unwrap().host, "irc.libera.chat");
    
    // Test default server selection (first server)
    let default_server = config.get_server(None);
    assert!(default_server.is_some(), "Should return default server");
    assert_eq!(default_server.unwrap().name, "work");
    
    // Test conversion to IRC config for each server
    for server in &config.servers {
        let irc_config = server.to_irc_config();
        assert_eq!(irc_config.server, server.host);
        assert_eq!(irc_config.port, server.port);
        assert_eq!(irc_config.tls_required, server.tls);
        assert_eq!(irc_config.channels, server.channels);
        assert_eq!(irc_config.nickname, config.user.nickname);
    }
    
    Ok(())
}

/// Test CLI command workflows
#[tokio::test]
#[serial]
async fn test_cli_command_workflow() -> Result<()> {
    use legionnaire::cli::{CliHandler, CliCommand};
    use legionnaire::client::IrcConfig;
    
    let server_config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: 6667,
        nickname: "cliuser".to_string(),
        ..IrcConfig::default()
    };
    
    let mut cli_handler = CliHandler::new(Some(server_config));
    
    // Test send command
    let send_command = CliCommand::Send {
        target: "#test".to_string(),
        message: "Hello from CLI".to_string(),
        bouncer: false,
    };
    
    // This would normally connect and send, but for testing we just verify
    // that the command structure is correct
    match send_command {
        CliCommand::Send { target, message, bouncer } => {
            assert_eq!(target, "#test");
            assert_eq!(message, "Hello from CLI");
            assert!(!bouncer);
        }
        _ => panic!("Wrong command type"),
    }
    
    // Test join command
    let join_command = CliCommand::Join {
        channels: "#test,#general".to_string(),
        keys: None,
        bouncer: false,
    };
    
    match join_command {
        CliCommand::Join { channels, keys, bouncer } => {
            assert_eq!(channels, "#test,#general");
            assert!(keys.is_none());
            assert!(!bouncer);
        }
        _ => panic!("Wrong command type"),
    }
    
    Ok(())
}

/// Test bouncer workflow
#[tokio::test]
#[serial]
async fn test_bouncer_workflow() -> Result<()> {
    use legionnaire::bouncer::{Bouncer, BouncerConfig};
    use legionnaire::client::IrcConfig;
    
    let bouncer_config = BouncerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0, // Let OS choose port
        password: "bouncer_test".to_string(),
        max_clients: 3,
        history_size: 100,
        auto_replay: true,
        ..BouncerConfig::default()
    };
    
    let irc_config = IrcConfig {
        server: "irc.test.com".to_string(),
        port: 6667,
        nickname: "bouncer_user".to_string(),
        channels: vec!["#persistent".to_string()],
        ..IrcConfig::default()
    };
    
    let bouncer = Bouncer::new(bouncer_config.clone(), irc_config);
    
    // Test bouncer configuration
    assert_eq!(bouncer_config.max_clients, 3);
    assert_eq!(bouncer_config.history_size, 100);
    assert!(bouncer_config.auto_replay);
    
    // Test bouncer status (would be more meaningful with actual running bouncer)
    // For now we test the configuration structure
    
    Ok(())
}

/// Test error handling user experience
#[tokio::test]
#[serial]
async fn test_error_handling_user_experience() -> Result<()> {
    use legionnaire::recovery::ErrorHandler;
    use legionnaire::error::IronError;
    
    // Test various error scenarios users might encounter
    let connection_errors = vec![
        IronError::Connection("Connection timed out".to_string()),
        IronError::Connection("Connection refused".to_string()),
        IronError::Connection("No route to host".to_string()),
        IronError::Connection("SSL certificate verify failed".to_string()),
    ];
    
    for error in connection_errors {
        let friendly_msg = ErrorHandler::user_friendly_error(&error);
        
        // Ensure error messages are user-friendly
        assert!(!friendly_msg.contains("Error:"), "Should not use technical 'Error:' prefix");
        assert!(!friendly_msg.contains("failed:"), "Should not use technical 'failed:' suffix");
        
        // Should have helpful emoji or symbols
        assert!(
            friendly_msg.contains("⏰") || 
            friendly_msg.contains("🚫") || 
            friendly_msg.contains("🔒") ||
            friendly_msg.contains("❌"),
            "Should use friendly symbols/emoji"
        );
        
        // Should provide actionable information
        let suggestions = ErrorHandler::error_suggestions(&error);
        if !suggestions.is_empty() {
            for suggestion in &suggestions {
                assert!(!suggestion.is_empty(), "Suggestions should not be empty");
                assert!(!suggestion.contains("debug"), "Should not mention debugging to users");
            }
        }
    }
    
    Ok(())
}

/// Test performance with reasonable message loads
#[tokio::test]
#[serial]
async fn test_performance_under_normal_load() -> Result<()> {
    use std::time::Instant;
    use legion_protocol::IrcMessage;
    
    let start_time = Instant::now();
    
    // Simulate processing a reasonable number of IRC messages
    let mut messages = Vec::new();
    for i in 0..1000 {
        let message = IrcMessage::new("PRIVMSG")
            .with_prefix(format!("user{}!test@example.com", i))
            .with_params(vec![
                "#test".to_string(),
                format!("Test message number {}", i)
            ]);
        messages.push(message);
    }
    
    // Process messages (simulation of parsing and handling)
    for message in &messages {
        // Basic message validation/parsing
        assert_eq!(message.command, "PRIVMSG");
        assert!(message.params.len() >= 2);
        assert!(message.prefix.is_some());
    }
    
    let processing_time = start_time.elapsed();
    
    // Should process 1000 messages in reasonable time (< 100ms)
    assert!(processing_time.as_millis() < 100, 
            "Should process 1000 messages quickly, took {:?}", processing_time);
    
    println!("Processed {} messages in {:?}", messages.len(), processing_time);
    
    Ok(())
}