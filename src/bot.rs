//! Bot Framework Core Infrastructure
//!
//! Provides the foundational bot capabilities that individual bot plugins can build upon.
//! This includes command parsing, permission handling, state management, and bot lifecycle.

use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error, debug, trace};
use serde::{Serialize, Deserialize};
use regex::Regex;
use async_trait::async_trait;

/// Bot framework configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfig {
    /// Bot command prefix (e.g., "!", "$", ".", etc.)
    pub command_prefix: String,
    /// Channels where bots are enabled
    pub enabled_channels: Vec<String>,
    /// Users with bot admin privileges
    pub admin_users: Vec<String>,
    /// Maximum command rate limit per user (commands per minute)
    pub rate_limit: u32,
    /// Enable/disable bot responses in private messages
    pub allow_private_commands: bool,
    /// Timeout for bot command execution in seconds
    pub command_timeout: u64,
    /// Enable detailed logging of bot activities
    pub debug_logging: bool,
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            command_prefix: "!".to_string(),
            enabled_channels: Vec::new(),
            admin_users: Vec::new(),
            rate_limit: 10, // 10 commands per minute
            allow_private_commands: true,
            command_timeout: 30,
            debug_logging: false,
        }
    }
}

/// Bot command context provided to bot handlers
#[derive(Debug, Clone)]
pub struct BotContext {
    /// The IRC message that triggered this command
    pub message: IrcMessage,
    /// Command name (without prefix)
    pub command: String,
    /// Command arguments
    pub args: Vec<String>,
    /// Full argument string (useful for free-form text)
    pub args_str: String,
    /// Channel or user the command was sent from
    pub source: String,
    /// Nickname of the user who sent the command
    pub sender: String,
    /// Whether this is a private message
    pub is_private: bool,
    /// Whether the sender has admin privileges
    pub is_admin: bool,
}

/// Bot command response
#[derive(Debug, Clone)]
pub enum BotResponse {
    /// Send a message to the same channel/user
    Reply(String),
    /// Send a message to a specific target
    SendTo { target: String, message: String },
    /// Send a private message to the command sender
    PrivateReply(String),
    /// Send a notice instead of a regular message
    Notice(String),
    /// Send an action (/me command)
    Action(String),
    /// No response
    None,
    /// Multiple responses
    Multiple(Vec<BotResponse>),
}

/// Bot plugin trait - individual bots implement this
#[async_trait]
pub trait Bot: Send + Sync {
    /// Bot information
    fn info(&self) -> BotInfo;
    
    /// Initialize the bot with configuration
    async fn init(&mut self, config: serde_json::Value) -> Result<()>;
    
    /// Get list of commands this bot handles
    fn commands(&self) -> Vec<BotCommand>;
    
    /// Handle a bot command
    async fn handle_command(&mut self, context: BotContext) -> Result<BotResponse>;
    
    /// Handle IRC messages (for bots that need to see all messages)
    async fn handle_message(&mut self, message: &IrcMessage) -> Result<Option<BotResponse>> {
        let _ = message; // Default implementation ignores messages
        Ok(None)
    }
    
    /// Bot startup hook
    async fn on_start(&mut self) -> Result<()> {
        Ok(())
    }
    
    /// Bot shutdown hook  
    async fn on_stop(&mut self) -> Result<()> {
        Ok(())
    }
    
    /// Periodic tick (called every minute by default)
    async fn on_tick(&mut self) -> Result<Vec<BotResponse>> {
        Ok(Vec::new())
    }
}

/// Bot metadata
#[derive(Debug, Clone)]
pub struct BotInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
}

/// Bot command definition
#[derive(Debug, Clone)]
pub struct BotCommand {
    /// Command name (without prefix)
    pub name: String,
    /// Command aliases
    pub aliases: Vec<String>,
    /// Command description
    pub description: String,
    /// Usage example
    pub usage: String,
    /// Minimum arguments required
    pub min_args: usize,
    /// Maximum arguments allowed (None = unlimited)
    pub max_args: Option<usize>,
    /// Whether admin privileges are required
    pub admin_only: bool,
    /// Channels where this command is allowed (empty = all enabled channels)
    pub allowed_channels: Vec<String>,
    /// Cooldown between uses of this command (in seconds)
    pub cooldown: u64,
}

/// Rate limiting state
struct RateLimit {
    user_commands: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    command_cooldowns: HashMap<String, chrono::DateTime<chrono::Utc>>, // user:command -> last_used
}

/// Bot framework manager
pub struct BotFramework {
    config: BotConfig,
    /// Registered bots
    bots: Arc<RwLock<HashMap<String, Box<dyn Bot>>>>,
    /// Command routing table
    command_routes: Arc<RwLock<HashMap<String, String>>>, // command -> bot_name
    /// Rate limiting state
    rate_limiter: Arc<RwLock<RateLimit>>,
    /// Message sender for bot responses
    response_tx: Option<mpsc::Sender<BotResponse>>,
    /// Command prefix regex
    prefix_regex: Regex,
}

impl BotFramework {
    pub fn new(config: BotConfig) -> Result<Self> {
        let prefix_escaped = regex::escape(&config.command_prefix);
        let prefix_regex = Regex::new(&format!(r"^{}(\w+)(?:\s+(.*))?", prefix_escaped))?;
        
        Ok(Self {
            config,
            bots: Arc::new(RwLock::new(HashMap::new())),
            command_routes: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimit {
                user_commands: HashMap::new(),
                command_cooldowns: HashMap::new(),
            })),
            response_tx: None,
            prefix_regex,
        })
    }
    
    /// Set the response channel for bot messages
    pub fn set_response_channel(&mut self, tx: mpsc::Sender<BotResponse>) {
        self.response_tx = Some(tx);
    }
    
    /// Register a bot
    pub async fn register_bot(&self, name: String, mut bot: Box<dyn Bot>) -> Result<()> {
        info!("Registering bot: {}", name);
        
        // Initialize the bot
        let empty_config = serde_json::json!({});
        bot.init(empty_config).await?;
        
        // Register commands
        let commands = bot.commands();
        let mut routes = self.command_routes.write().await;
        
        for cmd in &commands {
            routes.insert(cmd.name.clone(), name.clone());
            for alias in &cmd.aliases {
                routes.insert(alias.clone(), name.clone());
            }
        }
        
        debug!("Registered {} commands for bot '{}'", commands.len(), name);
        
        // Store the bot
        self.bots.write().await.insert(name.clone(), bot);
        
        // Start the bot
        if let Some(bot) = self.bots.write().await.get_mut(&name) {
            bot.on_start().await?;
        }
        
        info!("Bot '{}' registered and started successfully", name);
        Ok(())
    }
    
    /// Unregister a bot
    pub async fn unregister_bot(&self, name: &str) -> Result<()> {
        info!("Unregistering bot: {}", name);
        
        // Stop the bot
        if let Some(bot) = self.bots.write().await.get_mut(name) {
            bot.on_stop().await?;
        }
        
        // Remove from bots
        self.bots.write().await.remove(name);
        
        // Remove command routes
        let mut routes = self.command_routes.write().await;
        routes.retain(|_, bot_name| bot_name != name);
        
        info!("Bot '{}' unregistered successfully", name);
        Ok(())
    }
    
    /// Handle an IRC message (check for bot commands)
    pub async fn handle_message(&self, message: &IrcMessage) -> Result<Vec<BotResponse>> {
        let mut responses = Vec::new();
        
        // Let all bots see the message first
        let bots = self.bots.read().await;
        for (bot_name, bot_ref) in bots.iter() {
            // This is a bit complex due to async/await in loops with locks
            // In a real implementation, we'd need to handle this more carefully
            debug!("Letting bot '{}' see message", bot_name);
        }
        drop(bots);
        
        // Check if this is a command
        if let Some(target) = message.params.first() {
            if let Some(text) = message.params.get(1) {
                if let Some(context) = self.parse_command(message, target, text).await? {
                    if let Some(response) = self.execute_command(context).await? {
                        responses.push(response);
                    }
                }
            }
        }
        
        Ok(responses)
    }
    
    /// Parse a message to see if it's a bot command
    async fn parse_command(&self, message: &IrcMessage, target: &str, text: &str) -> Result<Option<BotContext>> {
        // Check if this matches our command pattern
        if let Some(captures) = self.prefix_regex.captures(text) {
            let command = captures.get(1).unwrap().as_str().to_lowercase();
            let args_str = captures.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            let args: Vec<String> = if args_str.trim().is_empty() {
                Vec::new()
            } else {
                args_str.split_whitespace().map(|s| s.to_string()).collect()
            };
            
            // Extract sender information
            let sender = message.prefix.as_ref()
                .and_then(|p| p.split('!').next())
                .unwrap_or("unknown")
                .to_string();
            
            // Check if this is a private message
            let is_private = !target.starts_with('#') && !target.starts_with('&');
            
            // Determine source (channel or private)
            let source = if is_private {
                sender.clone()
            } else {
                target.to_string()
            };
            
            // Check if sender is admin
            let is_admin = self.config.admin_users.contains(&sender);
            
            // Check if bots are enabled in this context
            if !is_private && !self.config.enabled_channels.is_empty() && 
               !self.config.enabled_channels.contains(&source) {
                trace!("Bot commands disabled in channel: {}", source);
                return Ok(None);
            }
            
            if is_private && !self.config.allow_private_commands {
                trace!("Private bot commands disabled");
                return Ok(None);
            }
            
            // Check if we have a handler for this command
            let routes = self.command_routes.read().await;
            if routes.contains_key(&command) {
                return Ok(Some(BotContext {
                    message: message.clone(),
                    command,
                    args,
                    args_str,
                    source,
                    sender,
                    is_private,
                    is_admin,
                }));
            }
        }
        
        Ok(None)
    }
    
    /// Execute a parsed bot command
    async fn execute_command(&self, context: BotContext) -> Result<Option<BotResponse>> {
        // Find the bot that handles this command
        let routes = self.command_routes.read().await;
        let bot_name = match routes.get(&context.command) {
            Some(name) => name.clone(),
            None => return Ok(None),
        };
        drop(routes);
        
        // Check rate limiting
        if !self.check_rate_limit(&context).await? {
            debug!("Rate limit exceeded for user: {}", context.sender);
            return Ok(Some(BotResponse::PrivateReply(
                "Rate limit exceeded. Please slow down!".to_string()
            )));
        }
        
        // Get bot and execute command
        let mut bots = self.bots.write().await;
        if let Some(bot) = bots.get_mut(&bot_name) {
            debug!("Executing command '{}' with bot '{}'", context.command, bot_name);
            
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(self.config.command_timeout),
                bot.handle_command(context.clone())
            ).await {
                Ok(Ok(response)) => {
                    // Update rate limit
                    self.update_rate_limit(&context).await;
                    return Ok(Some(response));
                }
                Ok(Err(e)) => {
                    error!("Bot '{}' error handling command '{}': {}", bot_name, context.command, e);
                    return Ok(Some(BotResponse::PrivateReply(
                        "Command failed. Please try again later.".to_string()
                    )));
                }
                Err(_) => {
                    warn!("Bot '{}' command '{}' timed out", bot_name, context.command);
                    return Ok(Some(BotResponse::PrivateReply(
                        "Command timed out.".to_string()
                    )));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Check if user is within rate limits
    async fn check_rate_limit(&self, context: &BotContext) -> Result<bool> {
        let mut limiter = self.rate_limiter.write().await;
        let now = chrono::Utc::now();
        let minute_ago = now - chrono::Duration::minutes(1);
        
        // Clean old entries and check rate
        let user_commands = limiter.user_commands
            .entry(context.sender.clone())
            .or_insert_with(Vec::new);
            
        user_commands.retain(|&time| time > minute_ago);
        
        Ok(user_commands.len() < self.config.rate_limit as usize)
    }
    
    /// Update rate limit tracking
    async fn update_rate_limit(&self, context: &BotContext) {
        let mut limiter = self.rate_limiter.write().await;
        let now = chrono::Utc::now();
        
        limiter.user_commands
            .entry(context.sender.clone())
            .or_insert_with(Vec::new)
            .push(now);
    }
    
    /// Start periodic tick for all bots
    pub fn start_tick_timer(&self) {
        let bots = Arc::clone(&self.bots);
        let response_tx = self.response_tx.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                if let Some(tx) = &response_tx {
                    let mut bots = bots.write().await;
                    for (name, bot) in bots.iter_mut() {
                        match bot.on_tick().await {
                            Ok(responses) => {
                                for response in responses {
                                    if let Err(e) = tx.send(response).await {
                                        error!("Failed to send bot response from '{}': {}", name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Bot '{}' tick error: {}", name, e);
                            }
                        }
                    }
                }
            }
        });
    }
    
    /// Get list of registered bots
    pub async fn list_bots(&self) -> Vec<String> {
        self.bots.read().await.keys().cloned().collect()
    }
    
    /// Get bot info
    pub async fn get_bot_info(&self, name: &str) -> Option<BotInfo> {
        if let Some(bot) = self.bots.read().await.get(name) {
            Some(bot.info())
        } else {
            None
        }
    }
    
    /// Get available commands
    pub async fn get_commands(&self) -> Result<Vec<(String, BotCommand)>> {
        let mut commands = Vec::new();
        let bots = self.bots.read().await;
        
        for (bot_name, bot) in bots.iter() {
            for cmd in bot.commands() {
                commands.push((bot_name.clone(), cmd));
            }
        }
        
        Ok(commands)
    }
}