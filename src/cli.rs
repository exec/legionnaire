//! CLI mode for atomic IRC operations
//! 
//! Provides a command-line interface for sending individual IRC commands
//! and interacting with bouncer daemon or standalone server connections.

use crate::plugin::manager::PluginManager;
use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::time::Duration;
use clap::Subcommand;
use tracing::{info, debug, error};

/// CLI commands for IRC operations
#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Send a message to a channel or user
    Send {
        /// Target channel or nickname
        target: String,
        /// Message to send
        message: String,
        /// Connect via bouncer instead of direct connection
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Join a channel
    Join {
        /// Channel(s) to join (comma-separated)
        channels: String,
        /// Channel key(s) if required
        #[arg(long)]
        keys: Option<String>,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Part from a channel
    Part {
        /// Channel(s) to part (comma-separated)
        channels: String,
        /// Part message
        #[arg(long)]
        message: Option<String>,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Set or remove topic
    Topic {
        /// Channel name
        channel: String,
        /// New topic (omit to view current)
        topic: Option<String>,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Change nickname
    Nick {
        /// New nickname
        nickname: String,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Set away status
    Away {
        /// Away message (omit to unset)
        message: Option<String>,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Execute raw IRC command
    Raw {
        /// Raw IRC command
        command: String,
        /// Connect via bouncer
        #[arg(long)]
        bouncer: bool,
    },
    
    /// Bouncer-specific commands
    Bouncer {
        #[command(subcommand)]
        command: BouncerCommand,
    },
}

/// Bouncer-specific subcommands
#[derive(Debug, Subcommand)]
pub enum BouncerCommand {
    /// Connect to bouncer daemon
    Connect {
        /// Bouncer address
        #[arg(default_value = "127.0.0.1")]
        host: String,
        /// Bouncer port
        #[arg(default_value = "6697")]
        port: u16,
        /// Authentication password
        #[arg(long)]
        password: Option<String>,
    },
    
    /// Get bouncer status
    Status,
    
    /// List connected clients
    Clients,
    
    /// Replay message history
    Replay {
        /// Target channel/nick to replay
        target: String,
        /// Number of messages to replay
        #[arg(long, default_value = "100")]
        count: usize,
        /// Start from timestamp (ISO 8601)
        #[arg(long)]
        since: Option<String>,
    },
    
    /// Detach from bouncer (keep connection alive)
    Detach {
        /// Leave away message
        #[arg(long)]
        away: Option<String>,
    },
}

/// CLI handler for executing IRC commands
pub struct CliHandler {
    /// Server configuration
    server_config: Option<crate::client::IrcConfig>,
    /// Bouncer connection details
    bouncer_config: Option<BouncerConfig>,
    /// Plugin manager for bouncer interaction
    plugin_manager: Option<PluginManager>,
}

/// Bouncer connection configuration
#[derive(Debug, Clone)]
struct BouncerConfig {
    host: String,
    port: u16,
    password: Option<String>,
}

impl CliHandler {
    /// Create a new CLI handler
    pub fn new(server_config: Option<crate::client::IrcConfig>) -> Self {
        Self {
            server_config,
            bouncer_config: None,
            plugin_manager: None,
        }
    }
    
    /// Execute a CLI command
    pub async fn execute(&mut self, command: CliCommand) -> Result<()> {
        match command {
            CliCommand::Send { target, message, bouncer } => {
                self.send_message(&target, &message, bouncer).await?;
            }
            
            CliCommand::Join { channels, keys, bouncer } => {
                self.join_channels(&channels, keys.as_deref(), bouncer).await?;
            }
            
            CliCommand::Part { channels, message, bouncer } => {
                self.part_channels(&channels, message.as_deref(), bouncer).await?;
            }
            
            CliCommand::Topic { channel, topic, bouncer } => {
                self.set_topic(&channel, topic.as_deref(), bouncer).await?;
            }
            
            CliCommand::Nick { nickname, bouncer } => {
                self.change_nick(&nickname, bouncer).await?;
            }
            
            CliCommand::Away { message, bouncer } => {
                self.set_away(message.as_deref(), bouncer).await?;
            }
            
            CliCommand::Raw { command, bouncer } => {
                self.send_raw(&command, bouncer).await?;
            }
            
            CliCommand::Bouncer { command } => {
                self.handle_bouncer_command(command).await?;
            }
        }
        
        Ok(())
    }
    
    /// Send a message
    async fn send_message(&self, target: &str, message: &str, use_bouncer: bool) -> Result<()> {
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec![target.to_string(), message.to_string()]);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Join channels
    async fn join_channels(&self, channels: &str, keys: Option<&str>, use_bouncer: bool) -> Result<()> {
        let mut params = vec![channels.to_string()];
        if let Some(keys) = keys {
            params.push(keys.to_string());
        }
        let msg = IrcMessage::new("JOIN").with_params(params);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Part channels
    async fn part_channels(&self, channels: &str, message: Option<&str>, use_bouncer: bool) -> Result<()> {
        let mut params = vec![channels.to_string()];
        if let Some(msg) = message {
            params.push(msg.to_string());
        }
        let msg = IrcMessage::new("PART").with_params(params);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Set topic
    async fn set_topic(&self, channel: &str, topic: Option<&str>, use_bouncer: bool) -> Result<()> {
        let mut params = vec![channel.to_string()];
        if let Some(topic) = topic {
            params.push(topic.to_string());
        }
        let msg = IrcMessage::new("TOPIC").with_params(params);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Change nickname
    async fn change_nick(&self, nickname: &str, use_bouncer: bool) -> Result<()> {
        let msg = IrcMessage::new("NICK")
            .with_params(vec![nickname.to_string()]);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Set away status
    async fn set_away(&self, message: Option<&str>, use_bouncer: bool) -> Result<()> {
        let params = if let Some(msg) = message {
            vec![msg.to_string()]
        } else {
            vec![]
        };
        let msg = IrcMessage::new("AWAY").with_params(params);
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Send raw IRC command
    async fn send_raw(&self, command: &str, use_bouncer: bool) -> Result<()> {
        let msg: IrcMessage = command.parse()
            .map_err(|e| anyhow!("Failed to parse IRC command: {}", e))?;
        
        self.send_irc_message(msg, use_bouncer).await
    }
    
    /// Handle bouncer-specific commands
    async fn handle_bouncer_command(&mut self, command: BouncerCommand) -> Result<()> {
        match command {
            BouncerCommand::Connect { host, port, password } => {
                self.bouncer_config = Some(BouncerConfig {
                    host: host.clone(),
                    port,
                    password,
                });
                
                info!("Configured bouncer connection: {}:{}", host, port);
                
                // Test connection
                self.test_bouncer_connection().await?;
            }
            
            BouncerCommand::Status => {
                let response = self.send_bouncer_command("status", &[] as &[&str]).await?;
                println!("{}", response);
            }
            
            BouncerCommand::Clients => {
                let response = self.send_bouncer_command("clients", &[] as &[&str]).await?;
                println!("{}", response);
            }
            
            BouncerCommand::Replay { target, count, since } => {
                let mut args = vec![target];
                args.push(count.to_string());
                if let Some(since) = since {
                    args.push(since);
                }
                
                let response = self.send_bouncer_command("replay", &args).await?;
                println!("{}", response);
            }
            
            BouncerCommand::Detach { away } => {
                if let Some(msg) = away {
                    self.set_away(Some(&msg), true).await?;
                }
                
                info!("Detached from bouncer");
            }
        }
        
        Ok(())
    }
    
    /// Send IRC message via direct connection or bouncer
    async fn send_irc_message(&self, msg: IrcMessage, use_bouncer: bool) -> Result<()> {
        if use_bouncer {
            self.send_via_bouncer(msg).await
        } else {
            self.send_direct(msg).await
        }
    }
    
    /// Send message directly to IRC server
    async fn send_direct(&self, msg: IrcMessage) -> Result<()> {
        let config = self.server_config.as_ref()
            .ok_or_else(|| anyhow!("No server configuration available"))?;
        
        let addr = format!("{}:{}", config.server, config.port);
        let mut stream = TcpStream::connect(&addr).await?;
        
        // Send message
        let msg_str = format!("{}\r\n", msg);
        stream.write_all(msg_str.as_bytes()).await?;
        
        // Wait for response
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();
        
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Ok(Some(line)) = lines.next_line().await {
                debug!("Server response: {}", line);
                if let Ok(response) = line.parse::<IrcMessage>() {
                    // Check for errors - numeric replies indicate completion
                    if response.command.chars().all(|c| c.is_ascii_digit()) {
                        break;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }).await.map_err(|e| anyhow::anyhow!("Timeout: {}", e))?;
        
        Ok(())
    }
    
    /// Send message via bouncer
    async fn send_via_bouncer(&self, msg: IrcMessage) -> Result<()> {
        let config = self.bouncer_config.as_ref()
            .ok_or_else(|| anyhow!("Bouncer not configured. Use 'bouncer connect' first"))?;
        
        let addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect(&addr).await?;
        
        // Authenticate if needed
        if let Some(password) = &config.password {
            let auth_msg = IrcMessage::new("PASS")
                .with_params(vec![password.clone()]);
            stream.write_all(format!("{}\r\n", auth_msg).as_bytes()).await?;
        }
        
        // Send message
        let msg_str = format!("{}\r\n", msg);
        stream.write_all(msg_str.as_bytes()).await?;
        
        info!("Message sent via bouncer");
        
        Ok(())
    }
    
    /// Send command to bouncer plugin
    async fn send_bouncer_command(&self, command: &str, args: &[impl AsRef<str>]) -> Result<String> {
        if let Some(plugin_manager) = &self.plugin_manager {
            let args: Vec<String> = args.iter().map(|s| s.as_ref().to_string()).collect();
            plugin_manager.execute_command("bouncer", command, &args).await
        } else {
            // Connect to bouncer via TCP and send command
            let config = self.bouncer_config.as_ref()
                .ok_or_else(|| anyhow!("Bouncer not configured"))?;
            
            // TODO: Implement bouncer control protocol
            Ok(format!("Bouncer command '{}' sent", command))
        }
    }
    
    /// Test bouncer connection
    async fn test_bouncer_connection(&self) -> Result<()> {
        let config = self.bouncer_config.as_ref()
            .ok_or_else(|| anyhow!("Bouncer not configured"))?;
        
        let addr = format!("{}:{}", config.host, config.port);
        let _stream = TcpStream::connect(&addr).await
            .map_err(|e| anyhow!("Failed to connect to bouncer: {}", e))?;
        
        info!("Successfully connected to bouncer at {}", addr);
        
        Ok(())
    }
}