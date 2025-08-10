//! Connection Recovery and Error Handling
//!
//! Provides robust error handling, automatic reconnection, and graceful degradation
//! for production IRC client usage.

use crate::error::{IronError, ConnectionState};
use crate::client::IrcConfig;
use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::time::{sleep, timeout};
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
    /// Maximum number of reconnection attempts (0 = unlimited)
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay in seconds
    pub initial_reconnect_delay: u64,
    /// Maximum reconnection delay in seconds (exponential backoff cap)
    pub max_reconnect_delay: u64,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum time to wait for server responses
    pub response_timeout: u64,
    /// Enable message queue during disconnection
    pub queue_messages: bool,
    /// Maximum queued messages during disconnection
    pub max_queued_messages: usize,
    /// Retry failed message sends
    pub retry_failed_sends: bool,
    /// Enable connection health monitoring
    pub enable_health_check: bool,
    /// Health check interval in seconds
    pub health_check_interval: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            auto_reconnect: true,
            max_reconnect_attempts: 10,
            initial_reconnect_delay: 5,
            max_reconnect_delay: 300, // 5 minutes
            connection_timeout: 30,
            response_timeout: 60,
            queue_messages: true,
            max_queued_messages: 100,
            retry_failed_sends: true,
            enable_health_check: true,
            health_check_interval: 60,
        }
    }
}

/// Recovery state tracking
#[derive(Debug, Clone)]
pub struct RecoveryState {
    pub connection_state: ConnectionState,
    pub reconnect_attempts: u32,
    pub last_attempt: Option<Instant>,
    pub next_reconnect_delay: Duration,
    pub health_check_failures: u32,
    pub total_disconnections: u32,
    pub uptime_start: Instant,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            connection_state: ConnectionState::Disconnected,
            reconnect_attempts: 0,
            last_attempt: None,
            next_reconnect_delay: Duration::from_secs(5),
            health_check_failures: 0,
            total_disconnections: 0,
            uptime_start: Instant::now(),
        }
    }
}

/// Queued message during disconnection
#[derive(Debug, Clone)]
struct QueuedMessage {
    message: IrcMessage,
    attempts: u32,
    queued_at: Instant,
}

/// Connection recovery manager
pub struct RecoveryManager {
    config: RecoveryConfig,
    state: RecoveryState,
    /// Messages queued during disconnection
    message_queue: VecDeque<QueuedMessage>,
    /// Channels to rejoin on reconnection
    channels_to_rejoin: Vec<String>,
    /// Last known nickname
    last_nickname: Option<String>,
    /// IRC configuration for reconnection
    irc_config: IrcConfig,
}

impl RecoveryManager {
    pub fn new(config: RecoveryConfig, irc_config: IrcConfig) -> Self {
        Self {
            config,
            state: RecoveryState::default(),
            message_queue: VecDeque::new(),
            channels_to_rejoin: Vec::new(),
            last_nickname: None,
            irc_config,
        }
    }
    
    /// Handle connection failure and decide whether to reconnect
    pub async fn handle_connection_failure(&mut self, error: &IronError) -> Result<bool> {
        self.state.total_disconnections += 1;
        self.state.connection_state = ConnectionState::Disconnected;
        
        error!("Connection failed: {}", error);
        
        if !self.config.auto_reconnect {
            info!("Auto-reconnect disabled, not attempting reconnection");
            return Ok(false);
        }
        
        if self.config.max_reconnect_attempts > 0 && 
           self.state.reconnect_attempts >= self.config.max_reconnect_attempts {
            error!("Maximum reconnection attempts ({}) exceeded", self.config.max_reconnect_attempts);
            return Err(anyhow!("Connection recovery failed after {} attempts", self.state.reconnect_attempts));
        }
        
        let delay = self.calculate_reconnect_delay();
        info!("Attempting reconnection in {:?} (attempt {} of {})", 
              delay, 
              self.state.reconnect_attempts + 1,
              if self.config.max_reconnect_attempts == 0 { "∞".to_string() } else { self.config.max_reconnect_attempts.to_string() }
        );
        
        sleep(delay).await;
        
        self.state.reconnect_attempts += 1;
        self.state.last_attempt = Some(Instant::now());
        
        Ok(true)
    }
    
    /// Handle successful reconnection
    pub async fn handle_successful_reconnection(&mut self) -> Result<Vec<IrcMessage>> {
        info!("Successfully reconnected after {} attempts", self.state.reconnect_attempts);
        
        self.state.connection_state = ConnectionState::Connected;
        self.state.reconnect_attempts = 0;
        self.state.next_reconnect_delay = Duration::from_secs(self.config.initial_reconnect_delay);
        self.state.health_check_failures = 0;
        
        let mut recovery_messages = Vec::new();
        
        // Restore nickname if needed
        if let Some(ref nick) = self.last_nickname {
            recovery_messages.push(IrcMessage::new("NICK").with_params(vec![nick.clone()]));
        }
        
        // Rejoin channels
        for channel in &self.channels_to_rejoin {
            info!("Rejoining channel: {}", channel);
            recovery_messages.push(IrcMessage::new("JOIN").with_params(vec![channel.clone()]));
        }
        
        // Send queued messages
        if self.config.queue_messages {
            while let Some(queued) = self.message_queue.pop_front() {
                if queued.queued_at.elapsed() < Duration::from_secs(300) { // 5 minute timeout
                    debug!("Sending queued message: {:?}", queued.message);
                    recovery_messages.push(queued.message);
                } else {
                    warn!("Dropping expired queued message");
                }
            }
        }
        
        Ok(recovery_messages)
    }
    
    /// Queue a message during disconnection
    pub fn queue_message(&mut self, message: IrcMessage) -> Result<()> {
        if !self.config.queue_messages {
            return Err(anyhow!("Message queuing is disabled"));
        }
        
        if self.message_queue.len() >= self.config.max_queued_messages {
            warn!("Message queue full, dropping oldest message");
            self.message_queue.pop_front();
        }
        
        self.message_queue.push_back(QueuedMessage {
            message,
            attempts: 0,
            queued_at: Instant::now(),
        });
        
        debug!("Queued message (queue size: {})", self.message_queue.len());
        Ok(())
    }
    
    /// Track joined channels for rejoin on reconnection
    pub fn track_channel_join(&mut self, channel: &str) {
        if !self.channels_to_rejoin.contains(&channel.to_string()) {
            self.channels_to_rejoin.push(channel.to_string());
            debug!("Tracking channel for rejoin: {}", channel);
        }
    }
    
    /// Stop tracking channel (on part)
    pub fn track_channel_part(&mut self, channel: &str) {
        self.channels_to_rejoin.retain(|c| c != channel);
        debug!("Stopped tracking channel: {}", channel);
    }
    
    /// Track nickname for restoration
    pub fn track_nickname(&mut self, nickname: &str) {
        self.last_nickname = Some(nickname.to_string());
        debug!("Tracking nickname: {}", nickname);
    }
    
    /// Check connection health
    pub async fn check_connection_health(&mut self) -> Result<bool> {
        if !self.config.enable_health_check {
            return Ok(true);
        }
        
        // In a real implementation, this would send a PING and wait for PONG
        // For now, we'll just check the connection state
        match self.state.connection_state {
            ConnectionState::Connected => {
                self.state.health_check_failures = 0;
                Ok(true)
            }
            _ => {
                self.state.health_check_failures += 1;
                warn!("Health check failed (failures: {})", self.state.health_check_failures);
                
                if self.state.health_check_failures >= 3 {
                    error!("Multiple health check failures, marking connection as unhealthy");
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
        }
    }
    
    /// Calculate next reconnection delay with exponential backoff
    fn calculate_reconnect_delay(&mut self) -> Duration {
        let delay = self.state.next_reconnect_delay;
        
        // Exponential backoff with jitter
        let next_delay = std::cmp::min(
            delay * 2,
            Duration::from_secs(self.config.max_reconnect_delay)
        );
        
        // Add jitter (±10%)
        let jitter_ms = (next_delay.as_millis() / 10) as u64;
        let jitter = Duration::from_millis(fastrand::u64(0..=jitter_ms * 2));
        
        self.state.next_reconnect_delay = if jitter > Duration::from_millis(jitter_ms) {
            next_delay + (jitter - Duration::from_millis(jitter_ms))
        } else {
            next_delay - (Duration::from_millis(jitter_ms) - jitter)
        };
        
        delay
    }
    
    /// Get recovery statistics
    pub fn get_stats(&self) -> RecoveryStats {
        RecoveryStats {
            connection_state: self.state.connection_state,
            reconnect_attempts: self.state.reconnect_attempts,
            total_disconnections: self.state.total_disconnections,
            uptime: self.state.uptime_start.elapsed(),
            queued_messages: self.message_queue.len(),
            channels_tracked: self.channels_to_rejoin.len(),
            health_check_failures: self.state.health_check_failures,
            next_reconnect_delay: if self.state.connection_state == ConnectionState::Connected {
                None
            } else {
                Some(self.state.next_reconnect_delay)
            },
        }
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: RecoveryConfig) {
        info!("Updating recovery configuration");
        self.config = config;
    }
    
    /// Reset recovery state (useful for manual reconnection)
    pub fn reset_recovery_state(&mut self) {
        info!("Resetting recovery state");
        self.state.reconnect_attempts = 0;
        self.state.next_reconnect_delay = Duration::from_secs(self.config.initial_reconnect_delay);
        self.state.health_check_failures = 0;
    }
    
    /// Clear message queue (useful when giving up on reconnection)
    pub fn clear_message_queue(&mut self) {
        let count = self.message_queue.len();
        self.message_queue.clear();
        if count > 0 {
            warn!("Cleared {} queued messages", count);
        }
    }
}

/// Recovery statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryStats {
    pub connection_state: ConnectionState,
    pub reconnect_attempts: u32,
    pub total_disconnections: u32,
    pub uptime: Duration,
    pub queued_messages: usize,
    pub channels_tracked: usize,
    pub health_check_failures: u32,
    pub next_reconnect_delay: Option<Duration>,
}

/// Enhanced error handling with user-friendly messages
pub struct ErrorHandler;

impl ErrorHandler {
    /// Convert technical errors to user-friendly messages
    pub fn user_friendly_error(error: &IronError) -> String {
        match error {
            IronError::Timeout(msg) if msg.contains("timeout") => {
                "⏰ Connection timed out. The server may be busy or your internet connection is slow.".to_string()
            }
            IronError::Connection(msg) if msg.contains("refused") => {
                "🚫 Connection refused. The server may be down or the address/port is incorrect.".to_string()
            }
            IronError::Tls(msg) if msg.contains("certificate") => {
                "🔒 SSL certificate error. The server's certificate may be invalid or expired.".to_string()
            }
            IronError::Auth(_) => {
                "🔐 Authentication failed. Check your nickname, password, or SASL credentials.".to_string()
            }
            IronError::InvalidMessage(msg) => {
                format!("📺 Channel error: {}", Self::simplify_channel_error(msg))
            }
            IronError::SecurityViolation(msg) => {
                format!("⚠️  Security issue: {}", msg)
            }
            IronError::Configuration(msg) => {
                format!("⚙️  Configuration problem: {}", msg)
            }
            _ => {
                format!("❌ Connection problem: {}", error)
            }
        }
    }
    
    /// Simplify channel error messages
    fn simplify_channel_error(msg: &str) -> String {
        if msg.contains("banned") {
            "You are banned from this channel".to_string()
        } else if msg.contains("invite") {
            "This channel is invite-only".to_string()
        } else if msg.contains("key") {
            "This channel requires a password".to_string()
        } else if msg.contains("limit") {
            "This channel is full".to_string()
        } else {
            msg.to_string()
        }
    }
    
    /// Generate helpful suggestions for common errors
    pub fn error_suggestions(error: &IronError) -> Vec<String> {
        match error {
            IronError::Timeout(msg) => {
                vec![
                    "Try connecting again in a few moments".to_string(),
                    "Check your internet connection".to_string(),
                    "Try a different server if the problem persists".to_string(),
                ]
            }
            IronError::Tls(msg) if msg.contains("certificate") => {
                vec![
                    "Try running with --no-cert-verify (not recommended for production)".to_string(),
                    "Contact the server administrator about the certificate issue".to_string(),
                ]
            }
            IronError::Auth(_) => {
                vec![
                    "Check your nickname and password in the configuration".to_string(),
                    "Make sure SASL is properly configured if required".to_string(),
                    "Try a different nickname if yours is already taken".to_string(),
                ]
            }
            _ => Vec::new(),
        }
    }
}