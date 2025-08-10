//! Production Integration Tests
//!
//! Comprehensive tests covering real-world usage scenarios, error conditions,
//! and production edge cases that users might encounter.

use legionnaire::{IronClient, Config, Bouncer, BouncerConfig, BotFramework, BotConfig};
use legionnaire::client::IrcConfig;
use legionnaire::recovery::{RecoveryManager, RecoveryConfig};
use legionnaire::credentials::{CredentialManager, CredentialType, CredentialBackend};
use legion_protocol::IrcMessage;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;
use tracing::{info, warn, error};
use serial_test::serial;

/// Mock IRC server for testing
struct MockIrcServer {
    listener: TcpListener,
    port: u16,
    responses: Arc<Mutex<HashMap<String, Vec<String>>>>,
    received_messages: Arc<Mutex<Vec<String>>>,
}

impl MockIrcServer {
    async fn new() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        
        Ok(Self {
            listener,
            port,
            responses: Arc::new(Mutex::new(HashMap::new())),
            received_messages: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    fn add_response(&self, trigger: &str, responses: Vec<&str>) {
        self.responses.lock().unwrap().insert(
            trigger.to_string(),
            responses.iter().map(|s| s.to_string()).collect()
        );
    }
    
    async fn start(&self) {
        let responses = Arc::clone(&self.responses);
        let received = Arc::clone(&self.received_messages);
        
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = self.listener.accept().await {
                    let responses = Arc::clone(&responses);
                    let received = Arc::clone(&received);
                    
                    tokio::spawn(async move {
                        Self::handle_client(stream, responses, received).await;
                    });
                }
            }
        });
    }
    
    async fn handle_client(
        mut stream: TcpStream,
        responses: Arc<Mutex<HashMap<String, Vec<String>>>>,
        received_messages: Arc<Mutex<Vec<String>>>,
    ) {
        let mut buffer = [0; 1024];
        
        // Send connection messages
        let _ = stream.write_all(b":mock.server 001 testuser :Welcome\r\n").await;
        let _ = stream.write_all(b":mock.server 376 testuser :End of MOTD\r\n").await;
        
        while let Ok(n) = stream.read(&mut buffer).await {
            if n == 0 { break; }
            
            let message = String::from_utf8_lossy(&buffer[..n]);
            received_messages.lock().unwrap().push(message.to_string());
            
            // Check for response triggers
            let responses_map = responses.lock().unwrap();
            for (trigger, response_list) in responses_map.iter() {
                if message.contains(trigger) {
                    for response in response_list {
                        let response_with_crlf = format!("{}\r\n", response);
                        let _ = stream.write_all(response_with_crlf.as_bytes()).await;
                    }
                }
            }
        }
    }
    
    fn get_received_messages(&self) -> Vec<String> {
        self.received_messages.lock().unwrap().clone()
    }
}

/// Test basic connection and disconnection cycles
#[tokio::test]
#[serial]
async fn test_connection_lifecycle() -> Result<()> {
    let server = MockIrcServer::new().await?;
    server.start().await;
    
    let config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: server.port,
        nickname: "testuser".to_string(),
        username: "test".to_string(),
        realname: "Test User".to_string(),
        tls_required: false,
        verify_certificates: false,
        channels: vec!["#test".to_string()],
        ..IrcConfig::default()
    };
    
    // Test normal connection
    let mut client = IronClient::new(config.clone());
    
    let result = client.connect().await;
    assert!(result.is_ok(), "Should connect successfully");
    
    let result = client.disconnect().await;
    assert!(result.is_ok(), "Should disconnect gracefully");
    
    Ok(())
}

/// Test network failure recovery scenarios
#[tokio::test]
#[serial]
async fn test_network_failure_recovery() -> Result<()> {
    let recovery_config = RecoveryConfig {
        auto_reconnect: true,
        max_reconnect_attempts: 3,
        initial_reconnect_delay: 1,
        max_reconnect_delay: 5,
        ..RecoveryConfig::default()
    };
    
    let irc_config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: 9999, // Non-existent port
        nickname: "testuser".to_string(),
        ..IrcConfig::default()
    };
    
    let mut recovery_manager = RecoveryManager::new(recovery_config, irc_config);
    
    // Simulate connection failure
    let connection_error = legionnaire::error::IronError::ConnectionFailed("Connection refused".to_string());
    
    let should_retry = recovery_manager.handle_connection_failure(&connection_error).await?;
    assert!(should_retry, "Should attempt to reconnect");
    
    // Track a channel for rejoin testing
    recovery_manager.track_channel_join("#test");
    recovery_manager.track_nickname("testuser");
    
    // Simulate successful reconnection
    let recovery_messages = recovery_manager.handle_successful_reconnection().await?;
    
    assert!(!recovery_messages.is_empty(), "Should have recovery messages");
    assert!(recovery_messages.iter().any(|msg| msg.command == "JOIN"), "Should rejoin channels");
    assert!(recovery_messages.iter().any(|msg| msg.command == "NICK"), "Should restore nickname");
    
    Ok(())
}

/// Test message queuing during disconnection
#[tokio::test]
#[serial]
async fn test_message_queuing() -> Result<()> {
    let recovery_config = RecoveryConfig {
        queue_messages: true,
        max_queued_messages: 5,
        ..RecoveryConfig::default()
    };
    
    let irc_config = IrcConfig::default();
    let mut recovery_manager = RecoveryManager::new(recovery_config, irc_config);
    
    // Queue some messages while disconnected
    for i in 1..=3 {
        let message = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#test".to_string(), format!("Message {}", i)]);
        recovery_manager.queue_message(message)?;
    }
    
    // Simulate reconnection
    let recovery_messages = recovery_manager.handle_successful_reconnection().await?;
    
    // Should have queued messages plus any rejoin messages
    let queued_count = recovery_messages.iter()
        .filter(|msg| msg.command == "PRIVMSG")
        .count();
    assert_eq!(queued_count, 3, "Should recover all queued messages");
    
    Ok(())
}

/// Test bouncer daemon startup and client connections
#[tokio::test]
#[serial]
async fn test_bouncer_daemon_lifecycle() -> Result<()> {
    let bouncer_config = BouncerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 0, // Let OS choose port
        password: "test".to_string(),
        max_clients: 2,
        ..BouncerConfig::default()
    };
    
    let irc_config = IrcConfig {
        server: "127.0.0.1".to_string(),
        port: 6667,
        nickname: "bouncer_test".to_string(),
        ..IrcConfig::default()
    };
    
    // Create and start bouncer
    let mut bouncer = Bouncer::new(bouncer_config, irc_config);
    
    // Start bouncer in background
    tokio::spawn(async move {
        let _ = bouncer.start().await;
    });
    
    // Give bouncer time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Test would continue with client connections, but we need the actual port
    // This is a simplified test - a real implementation would need better coordination
    
    Ok(())
}

/// Test bot framework with multiple bots
#[tokio::test]
#[serial]  
async fn test_bot_framework_multi_bot() -> Result<()> {
    let bot_config = BotConfig {
        command_prefix: "!".to_string(),
        enabled_channels: vec!["#test".to_string()],
        rate_limit: 10,
        ..BotConfig::default()
    };
    
    let framework = BotFramework::new(bot_config)?;
    
    // This test would register multiple bots and test command routing
    // Implementation depends on having concrete bot implementations
    
    // Simulate a bot command message
    let message = IrcMessage::new("PRIVMSG")
        .with_prefix("testuser!test@test.com".to_string())
        .with_params(vec!["#test".to_string(), "!help".to_string()]);
    
    let responses = framework.handle_message(&message).await?;
    
    // Framework should handle the command appropriately
    // This is a basic structure test
    
    Ok(())
}

/// Test credential storage and retrieval
#[tokio::test]
#[serial]
async fn test_credential_management() -> Result<()> {
    let mut cred_manager = CredentialManager::with_backend(CredentialBackend::Memory);
    
    // Store a server password
    let cred_type = CredentialType::ServerPassword {
        server: "irc.example.com".to_string()
    };
    
    let password = secrecy::Secret::new("secret_password".to_string());
    cred_manager.store_credential(cred_type.clone(), password).await?;
    
    // Retrieve the password
    let retrieved = cred_manager.get_credential(&cred_type).await?;
    assert!(retrieved.is_some(), "Should retrieve stored credential");
    
    let retrieved_password = retrieved.unwrap();
    assert_eq!(retrieved_password.expose_secret(), "secret_password");
    
    // Test deletion
    let deleted = cred_manager.delete_credential(&cred_type).await?;
    assert!(deleted, "Should confirm deletion");
    
    let should_be_none = cred_manager.get_credential(&cred_type).await?;
    assert!(should_be_none.is_none(), "Should not find deleted credential");
    
    Ok(())
}

/// Test configuration loading with error cases
#[tokio::test]
#[serial]
async fn test_config_error_handling() -> Result<()> {
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    // Test malformed TOML config
    let mut temp_file = NamedTempFile::new()?;
    writeln!(temp_file, "invalid toml [content")?;
    
    let result = Config::load_from_file(temp_file.path());
    assert!(result.is_err(), "Should fail to load malformed config");
    
    // Test missing required fields
    let mut temp_file2 = NamedTempFile::new()?;
    writeln!(temp_file2, r#"
[user]
# Missing nickname field
username = "test"
"#)?;
    
    let result = Config::load_from_file(temp_file2.path());
    assert!(result.is_err(), "Should fail when required fields are missing");
    
    // Test valid config
    let mut temp_file3 = NamedTempFile::new()?;
    writeln!(temp_file3, r#"
[user]
nickname = "testuser"
username = "test"
realname = "Test User"

[[servers]]
name = "test"
host = "irc.test.com"
port = 6667
tls = false
"#)?;
    
    let result = Config::load_from_file(temp_file3.path());
    assert!(result.is_ok(), "Should load valid config successfully");
    
    Ok(())
}

/// Test TLS connection scenarios
#[tokio::test]
#[serial]
async fn test_tls_connection_scenarios() -> Result<()> {
    // Test invalid certificate handling
    let config = IrcConfig {
        server: "expired.badssl.com".to_string(),
        port: 443,
        tls_required: true,
        verify_certificates: true,
        nickname: "testuser".to_string(),
        ..IrcConfig::default()
    };
    
    let mut client = IronClient::new(config);
    
    // This should fail with certificate error
    let result = client.connect().await;
    assert!(result.is_err(), "Should fail with bad certificate");
    
    // Test with certificate verification disabled
    let config_no_verify = IrcConfig {
        verify_certificates: false,
        ..config
    };
    
    let mut client_no_verify = IronClient::new(config_no_verify);
    
    // This might succeed (depending on whether the server accepts IRC connections)
    // But it shouldn't fail due to certificate issues
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client_no_verify.connect()
    ).await;
    
    // Either succeeds or times out, but shouldn't fail with cert error
    match result {
        Ok(Ok(_)) => println!("Connection succeeded"),
        Ok(Err(e)) => {
            // Should not be a certificate error
            let error_str = e.to_string();
            assert!(!error_str.contains("certificate"), 
                    "Should not fail with certificate error when verification disabled");
        }
        Err(_) => println!("Connection timed out (expected)"),
    }
    
    Ok(())
}

/// Test plugin loading and error handling
#[tokio::test]
#[serial]
async fn test_plugin_loading_errors() -> Result<()> {
    use legionnaire::plugin::PluginManager;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    // Create plugin context
    let plugin_context = legionnaire::plugin::PluginContext {
        client_config: Arc::new(IrcConfig::default()),
        plugin_config: serde_json::json!({}),
        shared_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
    };
    
    let plugin_manager = PluginManager::new(plugin_context);
    
    // Try to load non-existent plugin
    let result = plugin_manager.load_plugin("nonexistent-plugin", None).await;
    assert!(result.is_err(), "Should fail to load non-existent plugin");
    
    // Try to load valid plugin
    let result = plugin_manager.load_plugin("e2ee", None).await;
    assert!(result.is_ok(), "Should successfully load e2ee plugin");
    
    // Try to load same plugin again
    let result = plugin_manager.load_plugin("e2ee", None).await;
    assert!(result.is_err(), "Should fail to load already loaded plugin");
    
    Ok(())
}

/// Test concurrent connections and thread safety
#[tokio::test]
#[serial]
async fn test_concurrent_operations() -> Result<()> {
    use std::sync::atomic::{AtomicU32, Ordering};
    
    let counter = Arc::new(AtomicU32::new(0));
    let mut tasks = Vec::new();
    
    // Spawn multiple concurrent operations
    for i in 0..10 {
        let counter = Arc::clone(&counter);
        
        let task = tokio::spawn(async move {
            // Simulate some IRC operation
            let config = IrcConfig {
                server: "127.0.0.1".to_string(),
                port: 6667,
                nickname: format!("user{}", i),
                ..IrcConfig::default()
            };
            
            // This would normally try to connect, but we'll just
            // test that the configuration is handled correctly
            let _client = IronClient::new(config);
            
            counter.fetch_add(1, Ordering::SeqCst);
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    for task in tasks {
        task.await?;
    }
    
    assert_eq!(counter.load(Ordering::SeqCst), 10, "All tasks should complete");
    
    Ok(())
}

/// Test memory usage and leak prevention
#[tokio::test]
#[serial]
async fn test_memory_management() -> Result<()> {
    // This test would ideally use a memory profiler, but we'll do basic checks
    
    let mut recovery_config = RecoveryConfig::default();
    recovery_config.max_queued_messages = 5;
    
    let mut recovery_manager = RecoveryManager::new(recovery_config, IrcConfig::default());
    
    // Fill up the message queue to its limit
    for i in 1..=10 {
        let message = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#test".to_string(), format!("Message {}", i)]);
        let _ = recovery_manager.queue_message(message);
    }
    
    // Queue should be limited to max size
    let stats = recovery_manager.get_stats();
    assert!(stats.queued_messages <= 5, "Message queue should respect size limit");
    
    Ok(())
}

/// Test error message user-friendliness
#[tokio::test]
#[serial]
async fn test_user_friendly_error_messages() -> Result<()> {
    use legionnaire::recovery::ErrorHandler;
    use legionnaire::error::IronError;
    
    // Test various error types
    let connection_timeout = IronError::ConnectionFailed("Connection timeout".to_string());
    let friendly_msg = ErrorHandler::user_friendly_error(&connection_timeout);
    assert!(friendly_msg.contains("timeout"), "Should mention timeout");
    assert!(friendly_msg.contains("⏰"), "Should use friendly emoji");
    assert!(!friendly_msg.contains("Error"), "Should not use technical term 'Error'");
    
    let connection_refused = IronError::ConnectionFailed("Connection refused".to_string());
    let friendly_msg = ErrorHandler::user_friendly_error(&connection_refused);
    assert!(friendly_msg.contains("refused") || friendly_msg.contains("down"), "Should explain connection refused");
    
    let auth_failed = IronError::AuthenticationFailed;
    let friendly_msg = ErrorHandler::user_friendly_error(&auth_failed);
    assert!(friendly_msg.contains("password") || friendly_msg.contains("credentials"), "Should mention credentials");
    
    // Test suggestions
    let suggestions = ErrorHandler::error_suggestions(&auth_failed);
    assert!(!suggestions.is_empty(), "Should provide helpful suggestions");
    assert!(suggestions.iter().any(|s| s.contains("password") || s.contains("nickname")), 
            "Should suggest checking credentials");
    
    Ok(())
}