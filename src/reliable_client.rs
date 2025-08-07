use crate::connection_manager::{ConnectionManager, ConnectionEvent};
use iron_protocol::IrcMessage;
use iron_protocol::CapabilityHandler;
use crate::auth::SaslAuthenticator;
use crate::error::{IronError, Result, ConnectionState, DisconnectReason};
use crate::client::IrcConfig;

use tokio::sync::{mpsc, broadcast};
use tokio::time::{Duration, interval, timeout};
use crate::{iron_debug, iron_info, iron_warn, iron_error};
use secrecy::SecretString;

#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected,
    Disconnected { reason: DisconnectReason },
    Reconnecting { attempt: u32, max_attempts: u32 },
    MessageReceived(IrcMessage),
    RegistrationComplete,
    ChannelJoined(String),
    ChannelParted(String),
    NicknameChanged(String),
    Error(String),
}

pub struct ReliableIronClient {
    config: IrcConfig,
    connection_manager: ConnectionManager,
    cap_handler: CapabilityHandler,
    sasl_auth: Option<SaslAuthenticator>,
    
    // Event handling
    client_event_tx: broadcast::Sender<ClientEvent>,
    _client_event_rx: broadcast::Receiver<ClientEvent>,
    
    // Message handling
    message_tx: Option<mpsc::UnboundedSender<IrcMessage>>,
    message_rx: Option<mpsc::UnboundedReceiver<IrcMessage>>,
    
    // Auto-join channels (delayed until TUI is ready)
    pending_auto_join: Vec<String>,
    
    // Auto-reconnect settings
    auto_reconnect_enabled: bool,
    
    // Background task handles
    connection_event_handle: Option<tokio::task::JoinHandle<()>>,
    health_monitor_handle: Option<tokio::task::JoinHandle<()>>,
    message_processor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ReliableIronClient {
    pub fn new(config: IrcConfig) -> Self {
        let connection_manager = ConnectionManager::new(config.clone());
        let (client_event_tx, client_event_rx) = broadcast::channel(100);
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        Self {
            config,
            connection_manager,
            cap_handler: CapabilityHandler::new(),
            sasl_auth: None,
            
            client_event_tx,
            _client_event_rx: client_event_rx,
            
            message_tx: Some(message_tx),
            message_rx: Some(message_rx),
            
            pending_auto_join: Vec::new(),
            
            auto_reconnect_enabled: true,
            
            connection_event_handle: None,
            health_monitor_handle: None,
            message_processor_handle: None,
        }
    }

    // SASL configuration methods (same as original client)
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

    // Configuration methods
    pub fn enable_auto_reconnect(&mut self, enabled: bool) -> &mut Self {
        self.auto_reconnect_enabled = enabled;
        self
    }

    // Connection methods
    pub async fn connect(&mut self) -> Result<()> {
        iron_info!("reliable_client", "Starting reliable connection to {}:{}", self.config.server, self.config.port);
        
        // Start connection
        self.connection_manager.connect().await?;
        
        // Perform registration
        self.perform_registration().await?;
        
        // Start background tasks
        self.start_background_tasks().await?;
        
        // Emit connected event
        self.emit_client_event(ClientEvent::Connected).await;
        
        iron_info!("reliable_client", "Reliable connection established and registered");
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        iron_info!("reliable_client", "Disconnecting reliable client");
        
        // Stop background tasks
        self.stop_background_tasks().await;
        
        // Disconnect connection manager
        self.connection_manager.disconnect(DisconnectReason::UserRequested).await?;
        
        // Emit disconnected event
        self.emit_client_event(ClientEvent::Disconnected { 
            reason: DisconnectReason::UserRequested 
        }).await;
        
        iron_info!("reliable_client", "Reliable client disconnected");
        Ok(())
    }

    async fn start_background_tasks(&mut self) -> Result<()> {
        // Start connection event monitoring
        let conn_event_rx = self.connection_manager.subscribe_to_events();
        let client_event_tx = self.client_event_tx.clone();
        let auto_reconnect = self.auto_reconnect_enabled;
        
        self.connection_event_handle = Some(tokio::spawn(async move {
            Self::handle_connection_events(conn_event_rx, client_event_tx, auto_reconnect).await;
        }));

        // Start health monitoring
        // Note: This would need to be implemented with proper shared state
        // For now, we'll skip the health monitor task as it requires more complex sharing
        
        iron_info!("reliable_client", "Background tasks started");
        Ok(())
    }

    async fn stop_background_tasks(&mut self) {
        if let Some(handle) = self.connection_event_handle.take() {
            handle.abort();
        }
        
        if let Some(handle) = self.health_monitor_handle.take() {
            handle.abort();
        }
        
        if let Some(handle) = self.message_processor_handle.take() {
            handle.abort();
        }
        
        iron_info!("reliable_client", "Background tasks stopped");
    }

    async fn handle_connection_events(
        mut event_rx: broadcast::Receiver<ConnectionEvent>,
        client_event_tx: broadcast::Sender<ClientEvent>,
        _auto_reconnect: bool,
    ) {
        while let Ok(event) = event_rx.recv().await {
            match event.state {
                ConnectionState::Connected => {
                    let _ = client_event_tx.send(ClientEvent::Connected);
                }
                ConnectionState::Disconnected => {
                    if let Some(reason) = event.reason {
                        let _ = client_event_tx.send(ClientEvent::Disconnected { reason });
                    }
                }
                ConnectionState::Reconnecting { attempt, max_attempts } => {
                    let _ = client_event_tx.send(ClientEvent::Reconnecting { 
                        attempt, 
                        max_attempts 
                    });
                }
                ConnectionState::Failed => {
                    let _ = client_event_tx.send(ClientEvent::Error(
                        "Connection failed".to_string()
                    ));
                }
                _ => {}
            }
        }
    }

    async fn perform_registration(&mut self) -> Result<()> {
        iron_info!("reliable_client", "Starting IRC registration");

        // Send CAP LS
        self.send_raw("CAP LS 302").await?;
        
        // Send NICK and USER
        let nick_msg = IrcMessage::new("NICK").with_params(vec![self.config.nickname.clone()]);
        self.send_message(&nick_msg).await?;

        let user_msg = IrcMessage::new("USER").with_params(vec![
            self.config.username.clone(),
            "0".to_string(), 
            "*".to_string(),
            self.config.realname.clone(),
        ]);
        self.send_message(&user_msg).await?;

        // Wait for registration to complete
        self.wait_for_registration().await?;

        iron_info!("reliable_client", "IRC registration complete");
        Ok(())
    }

    async fn wait_for_registration(&mut self) -> Result<()> {
        let registration_timeout = Duration::from_secs(60);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < registration_timeout {
            match timeout(Duration::from_secs(5), self.read_message()).await {
                Ok(Ok(Some(message))) => {
                    if let Err(e) = self.handle_registration_message(message).await {
                        iron_error!("reliable_client", "Error handling registration message: {}", e);
                        return Err(e);
                    }
                    
                    let state = self.connection_manager.get_state().await;
                    if matches!(state, ConnectionState::Registered) {
                        return Ok(());
                    }
                }
                Ok(Ok(None)) => {
                    return Err(IronError::Connection("Connection closed during registration".to_string()));
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Err(_) => {
                    // Timeout, continue loop
                    continue;
                }
            }
        }

        Err(IronError::Connection("Registration timeout".to_string()))
    }

    async fn handle_registration_message(&mut self, message: IrcMessage) -> Result<()> {
        match message.command.as_str() {
            "001" => {
                // RPL_WELCOME - registration successful
                self.connection_manager.set_state(ConnectionState::Registered).await;
                self.emit_client_event(ClientEvent::RegistrationComplete).await;
                
                // NOTE: Auto-join is now handled by TUI after startup to avoid timing issues
                // Store channels for later auto-join
                self.pending_auto_join = self.config.channels.clone();
            }
            "CAP" => {
                if let Err(e) = self.handle_cap_message(&message).await {
                    iron_warn!("reliable_client", "Error handling CAP message: {}", e);
                }
            }
            "433" | "436" => {
                // Nickname in use
                iron_warn!("reliable_client", "Nickname {} is in use, trying alternative", self.config.nickname);
                let alt_nick = format!("{}_", self.config.nickname);
                let nick_msg = IrcMessage::new("NICK").with_params(vec![alt_nick]);
                self.send_message(&nick_msg).await?;
            }
            "ERROR" => {
                let error_msg = message.params.get(0)
                    .unwrap_or(&"Unknown error".to_string())
                    .clone();
                iron_error!("reliable_client", "Server error during registration: {}", error_msg);
                return Err(IronError::Connection(format!("Server error: {}", error_msg)));
            }
            _ => {
                // Forward other messages to the message channel
                if let Some(ref tx) = self.message_tx {
                    if let Err(_) = tx.send(message) {
                        iron_warn!("reliable_client", "Message channel closed");
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_cap_message(&mut self, message: &IrcMessage) -> Result<()> {
        if message.params.len() < 3 {
            return Ok(());
        }

        let subcommand = &message.params[1];
        
        match subcommand.as_str() {
            "LS" => {
                let is_complete = self.cap_handler.handle_cap_ls(&message.params[1..])?;
                if is_complete {
                    let caps_to_request = self.cap_handler.get_capabilities_to_request();
                    if !caps_to_request.is_empty() {
                        let req_msg = format!("CAP REQ :{}", caps_to_request.join(" "));
                        self.send_raw(&req_msg).await?;
                    } else {
                        self.send_raw("CAP END").await?;
                        self.cap_handler.set_negotiation_complete();
                    }
                }
            }
            "ACK" => {
                self.cap_handler.handle_cap_ack(&message.params[2..])?;
                
                // Handle SASL if enabled
                if self.cap_handler.is_capability_enabled("sasl") {
                    if let Some(ref sasl_auth) = self.sasl_auth {
                        let mechanisms = self.cap_handler.get_sasl_mechanisms();
                        if let Some(_mechanism) = sasl_auth.select_mechanism(&mechanisms) {
                            iron_info!("reliable_client", "SASL authentication would be performed here");
                            // TODO: Implement SASL authentication flow
                        }
                    }
                }
                
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
            }
            "NAK" => {
                self.cap_handler.handle_cap_nak(&message.params[2..])?;
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
            }
            _ => {}
        }

        Ok(())
    }

    // IRC operations
    pub async fn join_channel(&mut self, channel: &str) -> Result<()> {
        let join_msg = IrcMessage::new("JOIN").with_params(vec![channel.to_string()]);
        self.send_message(&join_msg).await?;
        self.emit_client_event(ClientEvent::ChannelJoined(channel.to_string())).await;
        iron_info!("reliable_client", "Joining channel: {}", channel);
        Ok(())
    }

    pub async fn part_channel(&mut self, channel: &str, reason: Option<&str>) -> Result<()> {
        let mut params = vec![channel.to_string()];
        if let Some(reason) = reason {
            params.push(reason.to_string());
        }

        let part_msg = IrcMessage::new("PART").with_params(params);
        self.send_message(&part_msg).await?;
        self.emit_client_event(ClientEvent::ChannelParted(channel.to_string())).await;
        iron_info!("reliable_client", "Parting channel: {}", channel);
        Ok(())
    }

    pub async fn send_privmsg(&mut self, target: &str, message: &str) -> Result<()> {
        let privmsg = IrcMessage::new("PRIVMSG")
            .with_params(vec![target.to_string(), message.to_string()]);
        
        self.send_message(&privmsg).await?;
        iron_debug!("reliable_client", "Sent message to {}: {}", target, message);
        Ok(())
    }

    pub async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
        self.connection_manager.send_message(message).await
    }

    pub async fn send_raw(&mut self, data: &str) -> Result<()> {
        let mut line = data.to_string();
        if !line.ends_with("\r\n") {
            line.push_str("\r\n");
        }

        // Create a raw message
        let raw_msg = IrcMessage::raw(&line);
        self.send_message(&raw_msg).await
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        self.connection_manager.read_message().await
    }

    // Event management
    pub fn subscribe_to_client_events(&self) -> broadcast::Receiver<ClientEvent> {
        self.client_event_tx.subscribe()
    }

    async fn emit_client_event(&self, event: ClientEvent) {
        if let Err(_) = self.client_event_tx.send(event) {
            iron_warn!("reliable_client", "No client event listeners available");
        }
    }

    // Status methods
    pub async fn get_connection_state(&self) -> ConnectionState {
        self.connection_manager.get_state().await
    }

    pub async fn is_connected(&self) -> bool {
        matches!(
            self.get_connection_state().await,
            ConnectionState::Connected | ConnectionState::Registered
        )
    }

    pub async fn is_registered(&self) -> bool {
        matches!(
            self.get_connection_state().await,
            ConnectionState::Registered
        )
    }

    pub async fn get_current_nickname(&self) -> String {
        let session = self.connection_manager.get_session_state().await;
        session.current_nickname
    }

    pub async fn get_joined_channels(&self) -> Vec<String> {
        let session = self.connection_manager.get_session_state().await;
        session.joined_channels
    }

    pub async fn get_connection_stats(&self) -> String {
        self.connection_manager.get_connection_info().await
    }

    // Manual connection management
    pub async fn force_reconnect(&mut self) -> Result<()> {
        iron_info!("reliable_client", "Manual reconnection requested");
        self.connection_manager.force_reconnect().await
    }

    // Main run loop
    pub async fn run(&mut self) -> Result<()> {
        let mut event_rx = self.subscribe_to_client_events();
        let mut message_interval = interval(Duration::from_millis(100));
        message_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Handle client events
                Ok(event) = event_rx.recv() => {
                    match event {
                        ClientEvent::Disconnected { reason } => {
                            iron_info!("reliable_client", "Disconnected: {}", reason);
                            
                            if self.auto_reconnect_enabled && 
                               !matches!(reason, DisconnectReason::UserRequested) {
                                iron_info!("reliable_client", "Auto-reconnect enabled, attempting reconnection");
                                if let Err(e) = self.connection_manager.start_auto_reconnect().await {
                                    iron_error!("reliable_client", "Auto-reconnect failed: {}", e);
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        ClientEvent::Error(msg) => {
                            iron_error!("reliable_client", "Client error: {}", msg);
                            break;
                        }
                        _ => {
                            iron_debug!("reliable_client", "Client event: {:?}", event);
                        }
                    }
                }
                
                // Handle incoming messages
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            if let Err(e) = self.handle_message(message.clone()).await {
                                iron_error!("reliable_client", "Error handling message: {}", e);
                            }
                            
                            // Forward to message channel
                            if let Some(ref tx) = self.message_tx {
                                if let Err(_) = tx.send(message) {
                                    iron_warn!("reliable_client", "Message channel closed");
                                }
                            }
                        }
                        Ok(None) => {
                            iron_info!("reliable_client", "Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            iron_error!("reliable_client", "Error reading message: {}", e);
                            // Error handling is done in connection manager
                            continue;
                        }
                    }
                }
                
                // Process queued messages periodically
                _ = message_interval.tick() => {
                    if let Err(e) = self.connection_manager.process_queued_messages().await {
                        iron_debug!("reliable_client", "Error processing queued messages: {}", e);
                    }
                }
            }
        }

        // Cleanup
        self.stop_background_tasks().await;
        Ok(())
    }

    async fn handle_message(&mut self, message: IrcMessage) -> Result<()> {
        iron_debug!("reliable_client", "Handling message: {}", message.command);

        match message.command.as_str() {
            "PING" => {
                let pong_msg = IrcMessage::new("PONG").with_params(message.params);
                self.send_message(&pong_msg).await?;
                iron_debug!("reliable_client", "Responded to PING");
            }
            "JOIN" => {
                if let Some(channel) = message.params.get(0) {
                    self.emit_client_event(ClientEvent::ChannelJoined(channel.clone())).await;
                }
            }
            "PART" => {
                if let Some(channel) = message.params.get(0) {
                    self.emit_client_event(ClientEvent::ChannelParted(channel.clone())).await;
                }
            }
            "NICK" => {
                if let Some(new_nick) = message.params.get(0) {
                    self.emit_client_event(ClientEvent::NicknameChanged(new_nick.clone())).await;
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn take_message_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<IrcMessage>> {
        self.message_rx.take()
    }

    // Get pending auto-join channels and clear the list
    pub fn get_pending_auto_join(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_auto_join)
    }
}

impl Drop for ReliableIronClient {
    fn drop(&mut self) {
        if let Some(handle) = self.connection_event_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.health_monitor_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.message_processor_handle.take() {
            handle.abort();
        }
    }
}

