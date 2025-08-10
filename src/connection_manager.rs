use crate::connection::SecureConnection;
use legion_protocol::IrcMessage;
use crate::error::{IronError, Result, ConnectionState, DisconnectReason};
use crate::client::IrcConfig;

use tokio::sync::{mpsc, broadcast, RwLock};
use tokio::time::{Duration, Instant, interval, sleep, timeout};
use std::sync::Arc;
use std::collections::VecDeque;
use crate::{iron_debug, iron_info, iron_warn, iron_error};

#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub timestamp: Instant,
    pub state: ConnectionState,
    pub reason: Option<DisconnectReason>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub connection_attempts: u32,
    pub successful_connections: u32,
    pub total_disconnects: u32,
    pub last_ping_time: Option<Instant>,
    pub last_pong_time: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u32,
    pub messages_received: u32,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            connection_attempts: 0,
            successful_connections: 0,
            total_disconnects: 0,
            last_ping_time: None,
            last_pong_time: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
        }
    }
}

#[derive(Debug)]
pub struct SessionState {
    pub current_nickname: String,
    pub joined_channels: Vec<String>,
    pub capabilities: Vec<String>,
    pub is_authenticated: bool,
    pub server_features: std::collections::HashMap<String, Option<String>>,
}

impl SessionState {
    pub fn new(nickname: String) -> Self {
        Self {
            current_nickname: nickname,
            joined_channels: Vec::new(),
            capabilities: Vec::new(),
            is_authenticated: false,
            server_features: std::collections::HashMap::new(),
        }
    }

    pub fn reset(&mut self, nickname: String) {
        self.current_nickname = nickname;
        self.joined_channels.clear();
        self.capabilities.clear();
        self.is_authenticated = false;
        self.server_features.clear();
    }

    pub fn add_channel(&mut self, channel: String) {
        if !self.joined_channels.contains(&channel) {
            self.joined_channels.push(channel);
        }
    }

    pub fn remove_channel(&mut self, channel: &str) {
        self.joined_channels.retain(|c| c != channel);
    }
}

#[derive(Debug)]
pub struct ExponentialBackoff {
    base_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
    jitter: bool,
    current_delay: Duration,
    attempt: u32,
}

impl ExponentialBackoff {
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            base_delay,
            max_delay,
            multiplier: 2.0,
            jitter: true,
            current_delay: base_delay,
            attempt: 0,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        self.attempt += 1;
        
        // Calculate exponential backoff
        let delay_secs = (self.base_delay.as_secs_f64() * self.multiplier.powi(self.attempt as i32))
            .min(self.max_delay.as_secs_f64());
        
        let mut delay = Duration::from_secs_f64(delay_secs);
        
        // Add jitter to prevent thundering herd
        if self.jitter {
            let jitter_amount = delay.as_millis() as f64 * 0.1; // 10% jitter
            let jitter = rand::random::<f64>() * jitter_amount * 2.0 - jitter_amount;
            let jittered_ms = (delay.as_millis() as f64 + jitter).max(0.0) as u64;
            delay = Duration::from_millis(jittered_ms);
        }
        
        self.current_delay = delay;
        delay
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
        self.current_delay = self.base_delay;
    }

    pub fn current_attempt(&self) -> u32 {
        self.attempt
    }
}

pub struct MessageQueue {
    queue: VecDeque<IrcMessage>,
    max_size: usize,
    priority_queue: VecDeque<IrcMessage>, // For high-priority messages like PONG
}

impl MessageQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_size,
            priority_queue: VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, message: IrcMessage, high_priority: bool) -> bool {
        if high_priority {
            self.priority_queue.push_back(message);
            true
        } else if self.queue.len() < self.max_size {
            self.queue.push_back(message);
            true
        } else {
            // Queue is full, drop oldest non-priority message
            self.queue.pop_front();
            self.queue.push_back(message);
            false
        }
    }

    pub fn dequeue(&mut self) -> Option<IrcMessage> {
        self.priority_queue.pop_front().or_else(|| self.queue.pop_front())
    }

    pub fn len(&self) -> usize {
        self.queue.len() + self.priority_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.priority_queue.is_empty()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.priority_queue.clear();
    }
}

pub struct ConnectionManager {
    config: IrcConfig,
    connection: Option<SecureConnection>,
    state: Arc<RwLock<ConnectionState>>,
    session_state: Arc<RwLock<SessionState>>,
    stats: Arc<RwLock<ConnectionStats>>,
    backoff: ExponentialBackoff,
    message_queue: MessageQueue,
    
    // Event handling
    event_tx: broadcast::Sender<ConnectionEvent>,
    _event_rx: broadcast::Receiver<ConnectionEvent>,
    
    // Internal communication
    reconnect_tx: Option<mpsc::UnboundedSender<()>>,
    reconnect_rx: Option<mpsc::UnboundedReceiver<()>>,
    
    // Health monitoring
    last_activity: Instant,
    ping_interval: Duration,
    pong_timeout: Duration,
    connection_timeout: Duration,
    
    // Network monitoring
    network_monitor_enabled: bool,
    last_network_check: Instant,
}

impl ConnectionManager {
    pub fn new(config: IrcConfig) -> Self {
        let (event_tx, event_rx) = broadcast::channel(100);
        let (reconnect_tx, reconnect_rx) = mpsc::unbounded_channel();
        
        let session_state = SessionState::new(config.nickname.clone());
        let backoff = ExponentialBackoff::new(
            Duration::from_secs(1),  // Start with 1 second
            Duration::from_secs(300), // Max 5 minutes
        );
        
        Self {
            connection: None,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            session_state: Arc::new(RwLock::new(session_state)),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
            backoff,
            message_queue: MessageQueue::new(1000), // Buffer up to 1000 messages
            
            event_tx,
            _event_rx: event_rx,
            
            reconnect_tx: Some(reconnect_tx),
            reconnect_rx: Some(reconnect_rx),
            
            last_activity: Instant::now(),
            ping_interval: config.ping_timeout,
            pong_timeout: Duration::from_secs(30),
            connection_timeout: config.connection_timeout,
            
            network_monitor_enabled: true,
            last_network_check: Instant::now(),
            
            config,
        }
    }

    // State management
    pub async fn get_state(&self) -> ConnectionState {
        *self.state.read().await
    }

    pub async fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.write().await;
        if *state != new_state {
            let old_state = *state;
            *state = new_state;
            drop(state);
            
            let event = ConnectionEvent {
                timestamp: Instant::now(),
                state: new_state,
                reason: None,
                message: Some(format!("State changed from {:?} to {:?}", old_state, new_state)),
            };
            
            if let Err(_) = self.event_tx.send(event) {
                iron_warn!("connection_manager", "No event listeners available");
            }
            
            iron_info!("connection_manager", "Connection state changed: {:?} -> {:?}", old_state, new_state);
        }
    }

    pub fn subscribe_to_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    pub async fn get_session_state(&self) -> SessionState {
        let session = self.session_state.read().await;
        SessionState {
            current_nickname: session.current_nickname.clone(),
            joined_channels: session.joined_channels.clone(),
            capabilities: session.capabilities.clone(),
            is_authenticated: session.is_authenticated,
            server_features: session.server_features.clone(),
        }
    }

    pub async fn get_stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    // Connection management
    pub async fn connect(&mut self) -> Result<()> {
        self.set_state(ConnectionState::Connecting).await;
        
        let mut stats = self.stats.write().await;
        stats.connection_attempts += 1;
        drop(stats);

        match self.attempt_connection().await {
            Ok(()) => {
                self.set_state(ConnectionState::Connected).await;
                let mut stats = self.stats.write().await;
                stats.successful_connections += 1;
                drop(stats);
                
                self.backoff.reset();
                self.last_activity = Instant::now();
                
                iron_info!("connection_manager", "Successfully connected to {}:{}", self.config.server, self.config.port);
                Ok(())
            }
            Err(e) => {
                self.set_state(ConnectionState::Failed).await;
                iron_error!("connection_manager", "Failed to connect: {}", e);
                Err(e)
            }
        }
    }

    async fn attempt_connection(&mut self) -> Result<()> {
        let connection = timeout(
            self.connection_timeout,
            SecureConnection::connect(
                &self.config.server,
                self.config.port,
                self.config.verify_certificates,
            )
        ).await
        .map_err(|_| IronError::Timeout("Connection timeout".to_string()))?
        .map_err(|e| IronError::Connection(format!("Connection failed: {}", e)))?;

        self.connection = Some(connection);
        Ok(())
    }

    pub async fn disconnect(&mut self, reason: DisconnectReason) -> Result<()> {
        iron_info!("connection_manager", "Disconnecting: {}", reason);
        
        let event = ConnectionEvent {
            timestamp: Instant::now(),
            state: ConnectionState::Disconnected,
            reason: Some(reason.clone()),
            message: Some(format!("Disconnecting: {}", reason)),
        };
        
        if let Err(_) = self.event_tx.send(event) {
            iron_warn!("connection_manager", "No event listeners available");
        }

        if let Some(mut conn) = self.connection.take() {
            if !matches!(reason, DisconnectReason::UserRequested) {
                // Try to send QUIT message for graceful disconnect
                let quit_msg = IrcMessage::new("QUIT")
                    .with_params(vec!["Connection manager disconnect".to_string()]);
                
                if let Err(e) = timeout(Duration::from_secs(5), conn.send_message(&quit_msg)).await {
                    iron_warn!("connection_manager", "Failed to send QUIT message: {}", e);
                }
            }
        }

        self.set_state(ConnectionState::Disconnected).await;
        
        let mut stats = self.stats.write().await;
        stats.total_disconnects += 1;
        drop(stats);

        Ok(())
    }

    // Auto-reconnection logic
    pub async fn start_auto_reconnect(&mut self) -> Result<()> {
        let max_attempts = self.config.reconnect_attempts;
        let mut attempt = 0;

        while attempt < max_attempts {
            attempt += 1;
            
            self.set_state(ConnectionState::Reconnecting { 
                attempt, 
                max_attempts 
            }).await;

            let delay = self.backoff.next_delay();
            iron_info!("connection_manager", "Reconnect attempt {}/{} in {:?}", attempt, max_attempts, delay);
            
            sleep(delay).await;

            match self.connect().await {
                Ok(()) => {
                    iron_info!("connection_manager", "Reconnection successful after {} attempts", attempt);
                    return self.restore_session_state().await;
                }
                Err(e) => {
                    iron_warn!("connection_manager", "Reconnect attempt {} failed: {}", attempt, e);
                    if attempt >= max_attempts {
                        iron_error!("connection_manager", "All reconnection attempts exhausted");
                        self.set_state(ConnectionState::Failed).await;
                        return Err(IronError::Reconnect("Max reconnection attempts reached".to_string()));
                    }
                }
            }
        }

        Ok(())
    }

    async fn restore_session_state(&mut self) -> Result<()> {
        iron_info!("connection_manager", "Restoring session state after reconnection");
        
        let session = self.session_state.read().await;
        let channels_to_rejoin = session.joined_channels.clone();
        let _nickname = session.current_nickname.clone();
        drop(session);

        // Re-register with the server
        self.set_state(ConnectionState::Registering).await;
        
        // This would be implemented in the actual IRC registration logic
        // For now, we'll mark as registered
        self.set_state(ConnectionState::Registered).await;
        
        // Rejoin channels
        for channel in channels_to_rejoin {
            let join_msg = IrcMessage::new("JOIN").with_params(vec![channel.clone()]);
            if let Err(e) = self.send_message(&join_msg).await {
                iron_warn!("connection_manager", "Failed to rejoin channel {}: {}", channel, e);
            } else {
                iron_info!("connection_manager", "Rejoined channel: {}", channel);
            }
        }

        iron_info!("connection_manager", "Session state restoration complete");
        Ok(())
    }

    // Health monitoring
    pub async fn start_health_monitor(&mut self) -> Result<()> {
        let mut ping_timer = interval(self.ping_interval);
        ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ping_timer.tick().await;
            
            let state = self.get_state().await;
            if !matches!(state, ConnectionState::Registered) {
                continue;
            }

            // Check if we've received a recent pong
            let stats = self.stats.read().await;
            let last_pong = stats.last_pong_time;
            let last_ping = stats.last_ping_time;
            drop(stats);

            if let (Some(ping_time), Some(pong_time)) = (last_ping, last_pong) {
                if ping_time > pong_time && ping_time.elapsed() > self.pong_timeout {
                    iron_error!("connection_manager", "PONG timeout detected, connection may be dead");
                    self.disconnect(DisconnectReason::PingTimeout).await?;
                    self.start_auto_reconnect().await?;
                    continue;
                }
            }

            // Send ping
            if let Err(e) = self.send_ping().await {
                iron_error!("connection_manager", "Failed to send ping: {}", e);
                self.disconnect(DisconnectReason::WriteError(e.to_string())).await?;
                self.start_auto_reconnect().await?;
            }
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        let ping_msg = IrcMessage::new("PING")
            .with_params(vec![self.config.server.clone()]);
        
        let mut stats = self.stats.write().await;
        stats.last_ping_time = Some(Instant::now());
        drop(stats);

        self.send_message(&ping_msg).await?;
        iron_debug!("connection_manager", "Sent PING to server");
        Ok(())
    }

    // Message handling
    pub async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
        if let Some(ref mut conn) = self.connection {
            match conn.send_message(message).await {
                Ok(()) => {
                    let mut stats = self.stats.write().await;
                    stats.messages_sent += 1;
                    stats.bytes_sent += message.to_string().len() as u64;
                    drop(stats);
                    
                    self.last_activity = Instant::now();
                    Ok(())
                }
                Err(e) => {
                    iron_error!("connection_manager", "Failed to send message: {}", e);
                    self.disconnect(DisconnectReason::WriteError(e.to_string())).await?;
                    
                    // Queue message for retry after reconnection
                    self.message_queue.enqueue(message.clone(), false);
                    
                    Err(e)
                }
            }
        } else {
            // Not connected, queue the message
            self.message_queue.enqueue(message.clone(), false);
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        if let Some(ref mut conn) = self.connection {
            match conn.read_message().await {
                Ok(Some(message)) => {
                    let mut stats = self.stats.write().await;
                    stats.messages_received += 1;
                    stats.bytes_received += message.to_string().len() as u64;
                    
                    // Handle PONG responses
                    if message.command == "PONG" {
                        stats.last_pong_time = Some(Instant::now());
                    }
                    drop(stats);
                    
                    self.last_activity = Instant::now();
                    self.update_session_state(&message).await;
                    
                    Ok(Some(message))
                }
                Ok(None) => {
                    iron_info!("connection_manager", "Connection closed by server");
                    self.disconnect(DisconnectReason::ServerError("Connection closed".to_string())).await?;
                    Ok(None)
                }
                Err(e) => {
                    iron_error!("connection_manager", "Failed to read message: {}", e);
                    self.disconnect(DisconnectReason::ReadError(e.to_string())).await?;
                    Err(e)
                }
            }
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    async fn update_session_state(&self, message: &IrcMessage) {
        let mut session = self.session_state.write().await;
        
        match message.command.as_str() {
            "JOIN" => {
                if let Some(channel) = message.params.get(0) {
                    // Check if this is our own join
                    if message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .map(|nick| nick == session.current_nickname)
                        .unwrap_or(false) 
                    {
                        session.add_channel(channel.clone());
                    }
                }
            }
            "PART" | "KICK" => {
                if let Some(channel) = message.params.get(0) {
                    // Check if this affects us
                    let target = if message.command == "KICK" {
                        message.params.get(1).map(|s| s.as_str())
                    } else {
                        message.prefix.as_ref().and_then(|p| p.split('!').next())
                    };
                    
                    if target.map(|t| t == session.current_nickname).unwrap_or(false) {
                        session.remove_channel(channel);
                    }
                }
            }
            "NICK" => {
                if let Some(new_nick) = message.params.get(0) {
                    if message.prefix.as_ref()
                        .and_then(|p| p.split('!').next())
                        .map(|nick| nick == session.current_nickname)
                        .unwrap_or(false) 
                    {
                        session.current_nickname = new_nick.clone();
                    }
                }
            }
            "001" => {
                // RPL_WELCOME - we're now registered
                session.is_authenticated = true;
                if let Some(new_nick) = message.params.get(0) {
                    session.current_nickname = new_nick.clone();
                }
            }
            _ => {}
        }
    }

    // Queue management
    pub async fn process_queued_messages(&mut self) -> Result<usize> {
        let mut processed = 0;
        
        while !self.message_queue.is_empty() {
            if let Some(message) = self.message_queue.dequeue() {
                if let Err(e) = self.send_message(&message).await {
                    // Put message back and stop processing
                    self.message_queue.enqueue(message, false);
                    return Err(e);
                }
                processed += 1;
            }
        }
        
        if processed > 0 {
            iron_info!("connection_manager", "Processed {} queued messages", processed);
        }
        
        Ok(processed)
    }

    // Network monitoring
    pub async fn check_network_connectivity(&mut self) -> bool {
        if !self.network_monitor_enabled {
            return true;
        }

        let now = Instant::now();
        if now.duration_since(self.last_network_check) < Duration::from_secs(30) {
            return true; // Don't check too frequently
        }
        
        self.last_network_check = now;

        // Simple network connectivity check
        // In a real implementation, you might want to check multiple endpoints
        match timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect("8.8.8.8:53") // Google DNS
        ).await {
            Ok(Ok(_)) => {
                iron_debug!("connection_manager", "Network connectivity check passed");
                true
            }
            _ => {
                iron_warn!("connection_manager", "Network connectivity check failed");
                false
            }
        }
    }

    // Manual controls
    pub async fn force_reconnect(&mut self) -> Result<()> {
        iron_info!("connection_manager", "Manual reconnection requested");
        self.disconnect(DisconnectReason::UserRequested).await?;
        self.backoff.reset(); // Reset backoff for manual reconnect
        self.connect().await
    }

    pub async fn get_connection_info(&self) -> String {
        let state = self.get_state().await;
        let stats = self.get_stats().await;
        let session = self.get_session_state().await;
        
        format!(
            "State: {}\nAttempts: {}\nSuccessful: {}\nDisconnects: {}\nChannels: {}\nNick: {}",
            state,
            stats.connection_attempts,
            stats.successful_connections,
            stats.total_disconnects,
            session.joined_channels.len(),
            session.current_nickname
        )
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        if self.connection.is_some() {
            iron_warn!("connection_manager", "ConnectionManager dropped while connected");
        }
    }
}