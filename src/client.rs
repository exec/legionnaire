use crate::connection::Connection;
use crate::error::{IronError, Result};
use legion_protocol::{IrcMessage, CapabilityHandler};
use crate::auth::SaslAuthenticator;
use crate::dos_protection::DosProtection;
use crate::dos_protection::DosProtectionConfig;

use tokio::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use crate::{iron_debug, iron_info, iron_warn, iron_error};
use secrecy::SecretString;

#[derive(Debug, Clone)]
pub struct IrcConfig {
    pub server: String,
    pub port: u16,
    pub nickname: String,
    pub username: String,
    pub realname: String,
    pub channels: Vec<String>,
    pub tls_required: bool,
    pub verify_certificates: bool,
    pub connection_timeout: Duration,
    pub ping_timeout: Duration,
    pub reconnect_attempts: u32,
    pub reconnect_delay: Duration,
}

impl Default for IrcConfig {
    fn default() -> Self {
        Self {
            server: "irc.libera.chat".to_string(),
            port: 6697,
            nickname: "legionnaire".to_string(),
            username: "legionnaire".to_string(),
            realname: "IronChat IRCv3 Client".to_string(),
            channels: Vec::new(),
            tls_required: true,
            verify_certificates: true,
            connection_timeout: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(300),
            reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(5),
        }
    }
}

pub struct IronClient {
    config: IrcConfig,
    connection: Option<Connection>,
    cap_handler: CapabilityHandler,
    sasl_auth: Option<SaslAuthenticator>,
    message_tx: Option<mpsc::UnboundedSender<IrcMessage>>,
    message_rx: Option<mpsc::UnboundedReceiver<IrcMessage>>,
    connected: bool,
    registered: bool,
    current_nick: String,
    dos_protection: Option<Arc<DosProtection>>,
    message_queue_size: usize,
    // Auto-join channels (delayed until TUI is ready)
    pending_auto_join: Vec<String>,
}

impl IronClient {
    pub fn new(config: IrcConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        
        Self {
            current_nick: config.nickname.clone(),
            connection: None,
            cap_handler: CapabilityHandler::new(),
            sasl_auth: None,
            message_tx: Some(tx),
            message_rx: Some(rx),
            connected: false,
            registered: false,
            dos_protection: None,
            message_queue_size: 0,
            pending_auto_join: Vec::new(),
            config,
        }
    }

    pub fn new_with_dos_protection(config: IrcConfig, dos_config: DosProtectionConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let dos_protection = Arc::new(DosProtection::new(dos_config));
        
        Self {
            current_nick: config.nickname.clone(),
            connection: None,
            cap_handler: CapabilityHandler::new(),
            sasl_auth: None,
            message_tx: Some(tx),
            message_rx: Some(rx),
            connected: false,
            registered: false,
            dos_protection: Some(dos_protection),
            message_queue_size: 0,
            pending_auto_join: Vec::new(),
            config,
        }
    }

    pub fn with_sasl_plain(&mut self, username: String, password: String) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth(username, SecretString::new(password));
        self.sasl_auth = Some(auth);
        self
    }

    pub fn with_sasl_external(&mut self) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_external_auth(None);
        self.sasl_auth = Some(auth);
        self
    }

    pub fn with_sasl_scram_sha256(&mut self, username: String, password: String) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_scram_sha256_auth(username, SecretString::new(password));
        self.sasl_auth = Some(auth);
        self
    }

    pub async fn connect(&mut self) -> Result<()> {
        iron_info!("client", "🔌 Connecting to {}:{}", self.config.server, self.config.port);
        
        if self.config.tls_required {
            println!("\x1b[95m🔐 Establishing TLS connection...\x1b[0m");
        } else {
            println!("\x1b[93m🔗 Establishing plain connection...\x1b[0m");
        }
        
        let connection = if let Some(ref dos) = self.dos_protection {
            Connection::connect_with_dos_protection(
                &self.config.server,
                self.config.port,
                self.config.tls_required,
                self.config.verify_certificates,
                Some(dos.clone()),
            ).await?
        } else {
            Connection::connect(
                &self.config.server,
                self.config.port,
                self.config.tls_required,
                self.config.verify_certificates,
            ).await?
        };
        
        if self.config.tls_required {
            println!("\x1b[92m🔒 TLS connection established\x1b[0m");
        } else {
            println!("\x1b[92m✅ Plain connection established\x1b[0m");
        }
        
        self.connection = Some(connection);
        self.connected = true;

        self.perform_registration().await?;

        iron_info!("client", "Successfully connected and registered to {}", self.config.server);
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut conn) = self.connection.take() {
            let quit_msg = IrcMessage::new("QUIT")
                .with_params(vec!["IronChat disconnecting".to_string()]);
            
            if let Err(e) = conn.send_message(&quit_msg).await {
                iron_warn!("client", "Failed to send QUIT message: {}", e);
            }
            
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        self.connected = false;
        self.registered = false;
        iron_info!("client", "Disconnected from {}", self.config.server);
        Ok(())
    }

    pub async fn join_channel(&mut self, channel: &str) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let join_msg = IrcMessage::new("JOIN").with_params(vec![channel.to_string()]);
        self.send_message(&join_msg).await?;
        
        iron_info!("client", "Joining channel: {}", channel);
        Ok(())
    }

    pub async fn part_channel(&mut self, channel: &str, reason: Option<&str>) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let mut params = vec![channel.to_string()];
        if let Some(reason) = reason {
            params.push(reason.to_string());
        }

        let part_msg = IrcMessage::new("PART").with_params(params);
        self.send_message(&part_msg).await?;
        
        iron_info!("client", "Parting channel: {}", channel);
        Ok(())
    }

    pub async fn send_privmsg(&mut self, target: &str, message: &str) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let privmsg = IrcMessage::new("PRIVMSG")
            .with_params(vec![target.to_string(), message.to_string()]);
        
        self.send_message(&privmsg).await?;
        iron_debug!("client", "Sent message to {}: {}", target, message);
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        if !self.connected {
            return Err(IronError::Connection("Not connected".to_string()));
        }

        let mut ping_interval = tokio::time::interval(self.config.ping_timeout);
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Start DoS protection cleanup task
        let cleanup_task = if let Some(ref dos) = self.dos_protection {
            let dos_clone = dos.clone();
            Some(tokio::spawn(async move {
                let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    cleanup_interval.tick().await;
                    dos_clone.cleanup_expired().await;
                }
            }))
        } else {
            None
        };

        let result = self.run_main_loop(ping_interval).await;

        // Cleanup the DoS protection task
        if let Some(task) = cleanup_task {
            task.abort();
        }

        self.connected = false;
        self.registered = false;
        result
    }

    async fn run_main_loop(&mut self, mut ping_interval: tokio::time::Interval) -> Result<()> {
        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            // Update queue size tracking for DoS protection
                            self.update_queue_size().await;
                            
                            if let Err(e) = self.handle_message(message).await {
                                iron_error!("client", "Error handling message: {}", e);
                                
                                // If it's a security violation, we might want to disconnect
                                if matches!(e, IronError::SecurityViolation(_)) {
                                    iron_warn!("client", "Security violation detected, disconnecting");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            iron_info!("client", "Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            iron_error!("client", "Error reading message: {}", e);
                            
                            // Handle DoS protection errors gracefully
                            if matches!(e, IronError::SecurityViolation(_)) {
                                iron_warn!("client", "DoS protection triggered: {}", e);
                                // Wait a bit before continuing
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                            break;
                        }
                    }
                }
                _ = ping_interval.tick() => {
                    if let Err(e) = self.send_ping().await {
                        iron_error!("client", "Failed to send ping: {}", e);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }

    pub fn current_nickname(&self) -> &str {
        &self.current_nick
    }
    
    pub fn get_config(&self) -> &IrcConfig {
        &self.config
    }
    
    pub fn has_capability(&self, capability: &str) -> bool {
        self.cap_handler.is_capability_enabled(capability)
    }

    // Get pending auto-join channels and clear the list
    pub fn get_pending_auto_join(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_auto_join)
    }

    pub fn server_name(&self) -> String {
        format!("{}:{}", self.config.server, self.config.port)
    }

    pub fn get_enabled_capabilities(&self) -> Vec<String> {
        // Return a list of enabled IRCv3 capabilities for display
        let mut caps = Vec::new();
        
        if self.cap_handler.is_capability_enabled("sasl") {
            caps.push("🔐 SASL".to_string());
        }
        if self.cap_handler.is_capability_enabled("server-time") {
            caps.push("⏰ Server-time".to_string());
        }
        if self.cap_handler.is_capability_enabled("message-tags") {
            caps.push("🏷️ Message-tags".to_string());
        }
        if self.cap_handler.is_capability_enabled("away-notify") {
            caps.push("💤 Away-notify".to_string());
        }
        if self.cap_handler.is_capability_enabled("account-tag") {
            caps.push("👤 Account-tag".to_string());
        }
        if self.cap_handler.is_capability_enabled("extended-join") {
            caps.push("🚪 Extended-join".to_string());
        }
        if self.cap_handler.is_capability_enabled("multi-prefix") {
            caps.push("⭐ Multi-prefix".to_string());
        }
        if self.cap_handler.is_capability_enabled("sts") {
            caps.push("🔒 STS".to_string());
        }
        if self.cap_handler.is_capability_enabled("+draft/react") {
            caps.push("😀 Reactions".to_string());
        }
        if self.cap_handler.is_capability_enabled("+draft/reply") {
            caps.push("↩️ Replies".to_string());
        }
        if self.cap_handler.is_capability_enabled("echo-message") {
            caps.push("📢 Echo-message".to_string());
        }
        if self.cap_handler.is_capability_enabled("batch") {
            caps.push("📦 Batch".to_string());
        }
        
        caps
    }

    pub fn is_capability_enabled(&self, capability: &str) -> bool {
        self.cap_handler.is_capability_enabled(capability)
    }

    /// Request chat history using IRCv3 CHATHISTORY capability
    pub async fn request_chat_history(
        &mut self,
        subcommand: &str,
        target: &str,
        selector: &str,
        limit: usize,
    ) -> Result<()> {
        if !self.has_capability("chathistory") {
            return Err(IronError::Connection("Server does not support CHATHISTORY".to_string()));
        }

        let command = format!("CHATHISTORY {} {} {} {}", subcommand, target, selector, limit);
        self.send_raw(&command).await
    }

    /// Request recent message history for a channel
    pub async fn request_recent_history(&mut self, channel: &str, limit: usize) -> Result<()> {
        self.request_chat_history("LATEST", channel, "*", limit).await
    }

    /// Request message history before a specific message ID or timestamp
    pub async fn request_history_before(&mut self, channel: &str, selector: &str, limit: usize) -> Result<()> {
        self.request_chat_history("BEFORE", channel, selector, limit).await
    }

    /// Request message history after a specific message ID or timestamp  
    pub async fn request_history_after(&mut self, channel: &str, selector: &str, limit: usize) -> Result<()> {
        self.request_chat_history("AFTER", channel, selector, limit).await
    }

    /// Request conversation targets (list of channels/DMs with history)
    pub async fn request_history_targets(&mut self, limit: usize) -> Result<()> {
        self.request_chat_history("TARGETS", "*", "*", limit).await
    }

    async fn perform_registration(&mut self) -> Result<()> {
        iron_info!("client", "🎭 Starting IRC registration");
        
        println!("\x1b[94m📋 Requesting server capabilities (CAP LS 302)...\x1b[0m");
        self.send_raw("CAP LS 302").await?;
        
        println!("\x1b[94m👤 Sending nickname: \x1b[93m{}\x1b[0m", self.config.nickname);
        let nick_msg = IrcMessage::new("NICK").with_params(vec![self.config.nickname.clone()]);
        self.send_message(&nick_msg).await?;

        println!("\x1b[94m📝 Sending user info: \x1b[93m{}\x1b[0m", self.config.username);
        let user_msg = IrcMessage::new("USER").with_params(vec![
            self.config.username.clone(),
            "0".to_string(), 
            "*".to_string(),
            self.config.realname.clone(),
        ]);
        self.send_message(&user_msg).await?;

        println!("\x1b[96m🔧 Negotiating IRCv3 capabilities...\x1b[0m");
        self.negotiate_capabilities().await?;

        Ok(())
    }

    async fn negotiate_capabilities(&mut self) -> Result<()> {
        // Use a more aggressive timeout for testing
        let timeout_duration = Duration::from_secs(10); // Much shorter for testing
        let negotiation_timeout = tokio::time::sleep(timeout_duration);
        tokio::pin!(negotiation_timeout);
        
        iron_info!("client", "🚀 Starting capability negotiation with {}s timeout", timeout_duration.as_secs());

        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            iron_info!("client", "📨 Negotiation received: {} {:?}", message.command, message.params);
                            
                            if self.handle_cap_message(&message).await? {
                                iron_info!("client", "✅ CAP negotiation completed successfully");
                                break;
                            }
                            
                            // Check for numeric 001 (RPL_WELCOME)
                            if message.command == "001" {
                                iron_info!("client", "🎉 Received 001 Welcome message!");
                                self.registered = true;
                                self.current_nick = message.params.first()
                                    .unwrap_or(&self.config.nickname)
                                    .clone();
                                iron_info!("client", "✅ Successfully registered with nick: {}", self.current_nick);
                                iron_info!("client", "📊 Registration flag set to: {}", self.registered);
                                
                                // FIXED: Don't sleep here - let the server send remaining messages
                                // We'll handle them in a separate phase
                                iron_info!("client", "🔚 Breaking from negotiation loop after 001");
                                break;
                            }
                            
                            // Handle other numeric responses during registration
                            if message.command.chars().all(|c| c.is_ascii_digit()) {
                                let code: u16 = message.command.parse().unwrap_or(0);
                                match code {
                                    002..=005 => {
                                        iron_debug!("client", "📋 Received registration message: {}", message.command);
                                        // Continue processing, these are expected
                                    }
                                    422 => {
                                        iron_debug!("client", "📋 Received MOTD message: {}", message.command);
                                        // MOTD related, continue
                                    }
                                    _ => {
                                        iron_debug!("client", "📋 Received numeric: {}", message.command);
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            iron_error!("client", "❌ Connection closed during negotiation");
                            return Err(IronError::Connection("Connection closed during registration".to_string()));
                        }
                        Err(e) => {
                            iron_error!("client", "❌ Error reading message during negotiation: {}", e);
                            return Err(e);
                        }
                    }
                }
                _ = &mut negotiation_timeout => {
                    iron_warn!("client", "Capability negotiation timeout, continuing without full capabilities");
                    break;
                }
            }
        }

        iron_info!("client", "🔍 Checking registration status: registered={}", self.registered);
        if !self.registered {
            iron_error!("client", "❌ Registration check failed - registered flag is false");
            return Err(IronError::Connection("Registration failed".to_string()));
        }

        // FIXED: Drain any remaining registration messages to prevent race conditions
        iron_info!("client", "🔄 Draining remaining registration messages...");
        let drain_timeout = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(drain_timeout);
        
        let mut drained_count = 0;
        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            drained_count += 1;
                            iron_debug!("client", "📦 Drained message {}: {} {:?}", drained_count, message.command, message.params);
                            
                            // Stop draining if we get a non-registration message
                            if !message.command.chars().all(|c| c.is_ascii_digit()) && 
                               message.command != "NOTICE" && message.command != "PRIVMSG" {
                                iron_debug!("client", "🛑 Stopping drain on non-registration message: {}", message.command);
                                break;
                            }
                            
                            // Prevent infinite drain
                            if drained_count >= 10 {
                                iron_debug!("client", "🛑 Stopping drain after {} messages", drained_count);
                                break;
                            }
                        }
                        Ok(None) => {
                            iron_debug!("client", "📡 Connection closed during message drain");
                            break;
                        }
                        Err(_) => {
                            iron_debug!("client", "❌ Error during message drain, stopping");
                            break;
                        }
                    }
                }
                _ = &mut drain_timeout => {
                    iron_debug!("client", "⏰ Message drain timeout reached, continuing");
                    break;
                }
            }
        }
        
        iron_info!("client", "✅ Registration complete. Current nick: {} (drained {} messages)", self.current_nick, drained_count);

        // Store auto-join channels for later processing by TUI (to avoid timing issues)
        self.pending_auto_join = self.config.channels.clone();
        iron_debug!("client", "Stored {} channels for delayed auto-join", self.pending_auto_join.len());

        Ok(())
    }

    async fn handle_cap_message(&mut self, message: &IrcMessage) -> Result<bool> {
        if message.command != "CAP" {
            return Ok(false);
        }

        iron_info!("client", "🔧 Received CAP message: {} {:?}", message.command, message.params);

        if message.params.len() < 2 {
            iron_warn!("client", "❌ CAP message has insufficient parameters: {:?}", message.params);
            return Ok(false);
        }

        let subcommand = &message.params[1];
        iron_info!("client", "🎯 Processing CAP subcommand: {}", subcommand);
        
        match subcommand.as_str() {
            "LS" => {
                let is_complete = self.cap_handler.handle_cap_ls(&message.params[1..])?;
                iron_info!("client", "📋 CAP LS processed, complete: {}", is_complete);
                if is_complete {
                    let caps_to_request = self.cap_handler.get_capabilities_to_request();
                    iron_info!("client", "🎯 Capabilities to request: {:?}", caps_to_request);
                    if !caps_to_request.is_empty() {
                        let req_msg = format!("CAP REQ :{}", caps_to_request.join(" "));
                        iron_info!("client", "📤 Sending: {}", req_msg);
                        self.send_raw(&req_msg).await?;
                        // Note: We'll wait for CAP ACK/NAK in the main negotiation loop
                    } else {
                        iron_info!("client", "📤 No capabilities to request, sending CAP END");
                        self.send_raw("CAP END").await?;
                        self.cap_handler.set_negotiation_complete();
                        return Ok(true);
                    }
                }
            }
            "ACK" => {
                iron_info!("client", "✅ Received CAP ACK");
                if message.params.len() >= 3 {
                    self.cap_handler.handle_cap_ack(&message.params[2..])?;
                    iron_info!("client", "✅ CAP ACK processed successfully");
                } else {
                    iron_warn!("client", "CAP ACK missing capability list");
                }
                
                if self.cap_handler.is_capability_enabled("sasl") {
                    if let Some(sasl_auth) = self.sasl_auth.clone() {
                        let mechanisms = self.cap_handler.get_sasl_mechanisms();
                        if let Some(mechanism) = sasl_auth.select_mechanism(&mechanisms) {
                            iron_info!("client", "🔐 SASL authentication mechanism selected: {:?}", mechanism);
                            
                            match self.perform_sasl_authentication(&sasl_auth, mechanism).await {
                                Ok(()) => {
                                    iron_info!("client", "✅ SASL authentication successful");
                                }
                                Err(e) => {
                                    iron_error!("client", "❌ SASL authentication failed: {}", e);
                                    return Err(e);
                                }
                            }
                        } else {
                            iron_warn!("client", "⚠️ No compatible SASL mechanisms available");
                        }
                    }
                }
                
                iron_info!("client", "📤 Sending CAP END to complete negotiation");
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
                return Ok(false); // FIXED: Continue waiting for 001 Welcome
            }
            "NAK" => {
                iron_info!("client", "❌ Received CAP NAK");
                if message.params.len() >= 3 {
                    self.cap_handler.handle_cap_nak(&message.params[2..])?;
                } else {
                    iron_warn!("client", "CAP NAK missing capability list");
                }
                iron_info!("client", "📤 Sending CAP END after NAK");
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
                return Ok(false); // FIXED: Continue waiting for 001 Welcome
            }
            "NEW" => {
                if message.params.len() > 2 {
                    let new_caps = self.cap_handler.handle_cap_new(&message.params[2])?;
                    if !new_caps.is_empty() {
                        let req_msg = format!("CAP REQ :{}", new_caps.join(" "));
                        self.send_raw(&req_msg).await?;
                    }
                }
            }
            "DEL" => {
                if message.params.len() >= 3 {
                    self.cap_handler.handle_cap_del(&message.params[2..])?;
                } else {
                    iron_warn!("client", "CAP DEL missing capability list");
                }
            }
            _ => {}
        }

        Ok(false)
    }

    pub async fn handle_message(&mut self, message: IrcMessage) -> Result<()> {
        iron_debug!("client", "Handling message: {}", message.command);

        match message.command.as_str() {
            "PING" => {
                let pong_msg = IrcMessage::new("PONG")
                    .with_params(message.params);
                self.send_message(&pong_msg).await?;
                iron_debug!("client", "Responded to PING");
            }
            "001" => {
                self.registered = true;
                self.current_nick = message.params.first()
                    .unwrap_or(&self.config.nickname)
                    .clone();
                iron_info!("client", "Successfully registered with nick: {}", self.current_nick);
            }
            "433" | "436" => {
                iron_warn!("client", "Nickname {} is in use, trying alternative", self.current_nick);
                self.current_nick = format!("{}_", self.current_nick);
                let nick_msg = IrcMessage::new("NICK").with_params(vec![self.current_nick.clone()]);
                self.send_message(&nick_msg).await?;
            }
            "ERROR" => {
                let default_error = "Unknown error".to_string();
                let error_msg = message.params.first().unwrap_or(&default_error);
                iron_error!("client", "Server error: {}", error_msg);
                return Err(IronError::Connection(format!("Server error: {error_msg}")));
            }
            _ => {
                if let Some(ref tx) = self.message_tx {
                    if tx.send(message).is_err() {
                        iron_warn!("client", "Message channel closed");
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
        if let Some(ref mut conn) = self.connection {
            conn.send_message(message).await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    pub async fn send_raw(&mut self, data: &str) -> Result<()> {
        if let Some(ref mut conn) = self.connection {
            conn.send_raw(data).await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        if let Some(ref mut conn) = self.connection {
            conn.read_message().await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        let ping_msg = IrcMessage::new("PING")
            .with_params(vec![self.config.server.clone()]);
        self.send_message(&ping_msg).await?;
        iron_debug!("client", "Sent PING to server");
        Ok(())
    }

    async fn perform_sasl_authentication(&mut self, _sasl_auth: &SaslAuthenticator, mechanism: &crate::auth::SaslMechanism) -> Result<()> {
        iron_info!("client", "🔐 Starting SASL authentication with integrated connection");
        
        if let Some(ref mut conn) = self.connection {
            let tls_active = conn.is_tls_active();
            
            // Use the connection's send_raw and read_message methods for SASL
            match mechanism {
                crate::auth::SaslMechanism::Plain { username, password, authzid } => {
                    self.authenticate_sasl_plain(username, password, authzid.as_deref(), tls_active).await?;
                }
                crate::auth::SaslMechanism::External { authzid } => {
                    self.authenticate_sasl_external(authzid.as_deref()).await?;
                }
                crate::auth::SaslMechanism::ScramSha256 { username: _, password: _ } => {
                    return Err(IronError::Auth("SCRAM-SHA-256 integration not yet complete".to_string()));
                }
            }
            
            iron_info!("client", "✅ SASL authentication completed successfully");
            Ok(())
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    async fn authenticate_sasl_plain(&mut self, username: &str, password: &secrecy::SecretString, authzid: Option<&str>, tls_active: bool) -> Result<()> {
        use secrecy::ExposeSecret;
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        
        if !tls_active {
            return Err(IronError::SecurityViolation("PLAIN authentication requires TLS".to_string()));
        }

        iron_info!("client", "Starting PLAIN authentication for user: {}", username);

        self.send_raw("AUTHENTICATE PLAIN").await?;

        // Wait for server response
        let response = self.read_message().await?;
        if let Some(msg) = response {
            if msg.command != "AUTHENTICATE" || msg.params.get(0) != Some(&"+".to_string()) {
                return Err(IronError::Auth("Unexpected server response".to_string()));
            }
        }

        let authz = authzid.unwrap_or("");
        let auth_string = format!("{}\0{}\0{}", authz, username, password.expose_secret());
        let encoded = BASE64.encode(auth_string.as_bytes());
        
        self.send_raw(&format!("AUTHENTICATE {}", encoded)).await?;

        // Wait for success/failure
        self.wait_for_sasl_completion().await
    }

    async fn authenticate_sasl_external(&mut self, authzid: Option<&str>) -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        
        iron_info!("client", "Starting EXTERNAL authentication");

        self.send_raw("AUTHENTICATE EXTERNAL").await?;

        // Wait for server response
        let response = self.read_message().await?;
        if let Some(msg) = response {
            if msg.command != "AUTHENTICATE" || msg.params.get(0) != Some(&"+".to_string()) {
                return Err(IronError::Auth("Unexpected server response".to_string()));
            }
        }

        let auth_data = match authzid {
            Some(authz) => BASE64.encode(authz.as_bytes()),
            None => "+".to_string(),
        };

        self.send_raw(&format!("AUTHENTICATE {}", auth_data)).await?;

        // Wait for success/failure
        self.wait_for_sasl_completion().await
    }

    async fn wait_for_sasl_completion(&mut self) -> Result<()> {
        let timeout = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    if let Ok(Some(message)) = message_result {
                        if let Ok(numeric_code) = message.command.parse::<u16>() {
                            match numeric_code {
                                900 | 903 => {
                                    iron_info!("client", "SASL authentication successful");
                                    return Ok(());
                                }
                                902 => return Err(IronError::Auth("Account unavailable".to_string())),
                                904 => return Err(IronError::Auth("Authentication failed".to_string())),
                                905 => return Err(IronError::Auth("Message too long".to_string())),
                                906 => return Err(IronError::Auth("Authentication aborted".to_string())),
                                907 => return Err(IronError::Auth("Already authenticated".to_string())),
                                _ => continue,
                            }
                        }
                    }
                }
                _ = &mut timeout => {
                    return Err(IronError::Auth("SASL authentication timeout".to_string()));
                }
            }
        }
    }

    async fn update_queue_size(&mut self) {
        if let Some(ref rx) = self.message_rx {
            self.message_queue_size = rx.len();
            
            // Update DoS protection with current queue size
            if let (Some(ref dos), Some(ref conn)) = (&self.dos_protection, &self.connection) {
                if let Err(e) = dos.update_queue_size(conn.connection_id(), self.message_queue_size).await {
                    iron_warn!("client", "Failed to update queue size in DoS protection: {}", e);
                }
            }
        }
    }

    pub fn get_dos_protection_stats(&self) -> Option<String> {
        if let (Some(ref _dos), Some(ref conn)) = (&self.dos_protection, &self.connection) {
            // This would return formatted statistics - implementation depends on needs
            Some(format!("Connection: {}, Queue size: {}", conn.connection_id(), self.message_queue_size))
        } else {
            None
        }
    }

    pub async fn get_connection_stats(&self) -> Option<crate::dos_protection::ConnectionStats> {
        if let (Some(ref dos), Some(ref conn)) = (&self.dos_protection, &self.connection) {
            dos.get_connection_stats(conn.connection_id()).await
        } else {
            None
        }
    }

    pub async fn get_global_stats(&self) -> Option<crate::dos_protection::GlobalStats> {
        if let Some(ref dos) = &self.dos_protection {
            Some(dos.get_global_stats().await)
        } else {
            None
        }
    }
}

impl Drop for IronClient {
    fn drop(&mut self) {
        if self.connected {
            iron_warn!("client", "IronClient dropped while still connected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = IrcConfig::default();
        let client = IronClient::new(config);
        
        assert!(!client.is_connected());
        assert!(!client.is_registered());
        assert_eq!(client.current_nickname(), "legionnaire");
    }

    #[test]
    fn test_config_defaults() {
        let config = IrcConfig::default();
        
        assert_eq!(config.server, "irc.libera.chat");
        assert_eq!(config.port, 6697);
        assert!(config.tls_required);
        assert!(config.verify_certificates);
    }
}