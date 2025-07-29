use ironchat::{ReliableIronClient, ConnectionState, DisconnectReason};
use ironchat::client::IrcConfig;
use ironchat::reliable_client::ClientEvent;
use tokio::time::{Duration, sleep};
use ironchat::{iron_info, iron_warn, iron_error};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    ironchat::logger::init_logger().expect("Failed to initialize logger");

    iron_info!("demo", "Starting Reliable IRC Client Demo");

    // Create configuration
    let config = IrcConfig {
        server: env::var("IRC_SERVER").unwrap_or_else(|_| "irc.libera.chat".to_string()),
        port: env::var("IRC_PORT")
            .unwrap_or_else(|_| "6697".to_string())
            .parse()
            .unwrap_or(6697),
        nickname: env::var("IRC_NICK").unwrap_or_else(|_| "ironchat_demo".to_string()),
        username: env::var("IRC_USER").unwrap_or_else(|_| "ironchat".to_string()),
        realname: "IronChat Reliable Demo".to_string(),
        channels: vec!["#ironchat-test".to_string()],
        tls_required: !env::var("IRC_NO_TLS").is_ok(),
        verify_certificates: !env::var("IRC_NO_CERT_VERIFY").is_ok(),
        connection_timeout: Duration::from_secs(30),
        ping_timeout: Duration::from_secs(120), // More frequent pings for demo
        reconnect_attempts: 10,                 // More attempts for demo
        reconnect_delay: Duration::from_secs(2),
    };

    iron_info!("demo", "Configuration: {}:{} as {}", config.server, config.port, config.nickname);

    // Create reliable client
    let mut client = ReliableIronClient::new(config.clone());
    
    // Configure SASL if credentials are provided
    if let (Ok(username), Ok(password)) = (env::var("IRC_SASL_USER"), env::var("IRC_SASL_PASS")) {
        iron_info!("demo", "Configuring SASL PLAIN authentication");
        client.with_sasl_plain(username, password);
    }

    // Enable auto-reconnect
    client.enable_auto_reconnect(true);

    // Subscribe to client events
    let mut event_rx = client.subscribe_to_client_events();
    
    // Spawn event handler
    let event_handle = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match event {
                ClientEvent::Connected => {
                    iron_info!("demo", "✅ Connected to IRC server");
                }
                ClientEvent::Disconnected { reason } => {
                    iron_warn!("demo", "❌ Disconnected: {}", reason);
                }
                ClientEvent::Reconnecting { attempt, max_attempts } => {
                    iron_info!("demo", "🔄 Reconnecting... attempt {}/{}", attempt, max_attempts);
                }
                ClientEvent::RegistrationComplete => {
                    iron_info!("demo", "✅ Registration complete");
                }
                ClientEvent::ChannelJoined(channel) => {
                    iron_info!("demo", "📥 Joined channel: {}", channel);
                }
                ClientEvent::ChannelParted(channel) => {
                    iron_info!("demo", "📤 Parted channel: {}", channel);
                }
                ClientEvent::NicknameChanged(nick) => {
                    iron_info!("demo", "👤 Nickname changed to: {}", nick);
                }
                ClientEvent::MessageReceived(message) => {
                    iron_info!("demo", "💬 Message: {} {}", message.command, message.params.join(" "));
                }
                ClientEvent::Error(msg) => {
                    iron_error!("demo", "❌ Error: {}", msg);
                }
            }
        }
    });

    // Connect to server
    match client.connect().await {
        Ok(()) => {
            iron_info!("demo", "Successfully connected to IRC server");
        }
        Err(e) => {
            iron_error!("demo", "Failed to connect: {}", e);
            return Err(e.into());
        }
    }

    // Demonstration sequence
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        
        // Demonstrate manual reconnection
        iron_info!("demo", "🔧 Demonstrating manual reconnection in 10 seconds...");
        sleep(Duration::from_secs(10)).await;
        
        // Force reconnect (this would normally be triggered by network issues)
        iron_info!("demo", "🔧 Forcing reconnection...");
        // Note: We can't call force_reconnect here because we don't have mutable access
        // In a real application, you'd trigger this through commands or other mechanisms
    });

    // Run client with demonstration messages
    let mut message_rx = client.take_message_receiver().unwrap();
    let demo_handle = tokio::spawn(async move {
        let mut message_count = 0;
        
        while let Some(message) = message_rx.recv().await {
            message_count += 1;
            
            match message.command.as_str() {
                "PRIVMSG" => {
                    let channel = message.params.get(0).map(|s| s.as_str()).unwrap_or("unknown");
                    let text = message.params.get(1).map(|s| s.as_str()).unwrap_or("");
                    let sender = message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .unwrap_or("unknown");
                    
                    iron_info!("demo", "💬 [{}] <{}> {}", channel, sender, text);
                }
                "JOIN" => {
                    let channel = message.params.get(0).map(|s| s.as_str()).unwrap_or("unknown");
                    let user = message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .unwrap_or("unknown");
                    
                    iron_info!("demo", "📥 {} joined {}", user, channel);
                }
                "PART" => {
                    let channel = message.params.get(0).map(|s| s.as_str()).unwrap_or("unknown");
                    let user = message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .unwrap_or("unknown");
                    
                    iron_info!("demo", "📤 {} parted {}", user, channel);
                }
                "QUIT" => {
                    let user = message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .unwrap_or("unknown");
                    let reason = message.params.get(0).map(|s| s.as_str()).unwrap_or("");
                    
                    iron_info!("demo", "👋 {} quit: {}", user, reason);
                }
                _ => {
                    iron_info!("demo", "📨 {}: {}", message.command, message.params.join(" "));
                }
            }
            
            // Demonstrate connection resilience after processing some messages
            if message_count == 50 {
                iron_info!("demo", "🔧 Processed {} messages. Connection is stable!", message_count);
            }
        }
    });

    // Main client loop
    iron_info!("demo", "🚀 Starting main client loop...");
    match client.run().await {
        Ok(()) => {
            iron_info!("demo", "Client run completed successfully");
        }
        Err(e) => {
            iron_error!("demo", "Client run failed: {}", e);
        }
    }

    // Cleanup
    event_handle.abort();
    demo_handle.abort();
    
    iron_info!("demo", "Demo completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reliable_client_creation() {
        let config = IrcConfig::default();
        let client = ReliableIronClient::new(config);
        
        // Test initial state
        assert_eq!(client.get_connection_state().await, ConnectionState::Disconnected);
        assert!(!client.is_connected().await);
        assert!(!client.is_registered().await);
    }

    #[tokio::test]
    async fn test_connection_stats() {
        let config = IrcConfig::default();
        let client = ReliableIronClient::new(config);
        
        let stats = client.get_connection_stats().await;
        assert!(stats.contains("State: Disconnected"));
        assert!(stats.contains("Attempts: 0"));
    }
}