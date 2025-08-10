//! IRC Bouncer Core Module
//! 
//! Provides persistent IRC connections that clients can attach/detach from.
//! Maintains message history, channel state, and handles reconnections.

use crate::client::IrcConfig;
use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn, error, debug};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Maximum message history per channel/query
const MAX_HISTORY_SIZE: usize = 5000;

/// Bouncer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BouncerConfig {
    /// Listen address for client connections
    pub listen_addr: String,
    /// Listen port for client connections
    pub listen_port: u16,
    /// Password for client authentication
    pub password: String,
    /// Enable SSL/TLS for client connections
    pub use_tls: bool,
    /// Maximum clients allowed
    pub max_clients: usize,
    /// Message history size per target
    pub history_size: usize,
    /// Automatically replay history on connect
    pub auto_replay: bool,
    /// Keep-alive interval in seconds
    pub keepalive_interval: u64,
}

impl Default for BouncerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 6697,
            password: "".to_string(),
            use_tls: false,
            max_clients: 10,
            history_size: MAX_HISTORY_SIZE,
            auto_replay: true,
            keepalive_interval: 60,
        }
    }
}

/// IRC connection state maintained by bouncer
#[derive(Debug, Clone)]
struct ConnectionState {
    /// Current nickname
    pub nick: String,
    /// Joined channels
    pub channels: HashMap<String, ChannelState>,
    /// Server capabilities
    pub capabilities: Vec<String>,
    /// Away status
    pub away_message: Option<String>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
}

/// Channel state
#[derive(Debug, Clone)]
struct ChannelState {
    /// Channel topic
    pub topic: Option<String>,
    /// Channel modes
    pub modes: String,
    /// Users in channel
    pub users: HashMap<String, String>, // nick -> modes
    /// Join timestamp
    pub joined_at: DateTime<Utc>,
}

/// Message history storage
struct MessageHistory {
    /// History per target (channel/nick)
    targets: HashMap<String, VecDeque<HistoryEntry>>,
    /// Maximum size per target
    max_size: usize,
}

/// History entry
#[derive(Debug, Clone)]
struct HistoryEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// IRC message
    pub message: IrcMessage,
    /// Whether this was sent by us
    pub sent_by_us: bool,
}

/// Connected client info
struct ClientConnection {
    /// Client identifier
    pub id: String,
    /// Client address
    pub addr: String,
    /// Client capabilities
    pub capabilities: Vec<String>,
    /// Authentication status
    pub authenticated: bool,
    /// Attach timestamp
    pub attached_at: DateTime<Utc>,
}

/// Bouncer control commands
enum BouncerCommand {
    /// Client attached
    ClientAttached(String),
    /// Client detached
    ClientDetached(String),
    /// Replay history for target
    ReplayHistory(String, Option<String>), // client_id, target
    /// Update configuration
    UpdateConfig(BouncerConfig),
    /// Get status
    GetStatus(mpsc::Sender<BouncerStatus>),
}

/// Bouncer status
#[derive(Debug, Clone, Serialize)]
pub struct BouncerStatus {
    pub state: String,
    pub uptime: u64,
    pub connected_clients: usize,
    pub channels: Vec<String>,
    pub history_size: usize,
    pub last_activity: DateTime<Utc>,
}

/// Main bouncer daemon
pub struct Bouncer {
    config: BouncerConfig,
    irc_config: IrcConfig,
    /// Active IRC connection state
    connection_state: Arc<RwLock<ConnectionState>>,
    /// Message history storage
    history: Arc<RwLock<MessageHistory>>,
    /// Connected clients
    clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    /// Control channel for bouncer commands
    control_tx: mpsc::Sender<BouncerCommand>,
    control_rx: Option<mpsc::Receiver<BouncerCommand>>,
}

impl Bouncer {
    pub fn new(config: BouncerConfig, irc_config: IrcConfig) -> Self {
        let (tx, rx) = mpsc::channel(100);
        
        Self {
            config: config.clone(),
            irc_config,
            connection_state: Arc::new(RwLock::new(ConnectionState {
                nick: String::new(),
                channels: HashMap::new(),
                capabilities: Vec::new(),
                away_message: None,
                last_activity: Utc::now(),
            })),
            history: Arc::new(RwLock::new(MessageHistory {
                targets: HashMap::new(),
                max_size: config.history_size,
            })),
            clients: Arc::new(RwLock::new(HashMap::new())),
            control_tx: tx,
            control_rx: Some(rx),
        }
    }
    
    /// Start the bouncer daemon
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting bouncer daemon on {}:{}", self.config.listen_addr, self.config.listen_port);
        
        // Start IRC connection
        self.start_irc_connection().await?;
        
        // Start client listener
        self.start_listener().await?;
        
        // Start control loop
        let control_rx = self.control_rx.take().unwrap();
        let connection_state = Arc::clone(&self.connection_state);
        let history = Arc::clone(&self.history);
        let clients = Arc::clone(&self.clients);
        
        tokio::spawn(async move {
            Self::control_loop(control_rx, connection_state, history, clients).await;
        });
        
        info!("Bouncer daemon started successfully");
        Ok(())
    }
    
    /// Start IRC connection
    async fn start_irc_connection(&self) -> Result<()> {
        // TODO: Implement IRC client connection
        // This would use the existing IronClient but in persistent mode
        info!("Starting IRC connection to {}:{}", self.irc_config.server, self.irc_config.port);
        Ok(())
    }
    
    /// Start the client listener
    async fn start_listener(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Bouncer listening on {}", addr);
        
        let clients = Arc::clone(&self.clients);
        let config = self.config.clone();
        let control_tx = self.control_tx.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Bouncer client connected from {}", addr);
                        
                        let client_id = Uuid::new_v4().to_string();
                        let client = ClientConnection {
                            id: client_id.clone(),
                            addr: addr.to_string(),
                            capabilities: Vec::new(),
                            authenticated: config.password.is_empty(),
                            attached_at: Utc::now(),
                        };
                        
                        clients.write().await.insert(client_id.clone(), client);
                        
                        // Handle client in separate task
                        let clients = Arc::clone(&clients);
                        let control_tx = control_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_client(client_id, stream, clients, control_tx).await {
                                error!("Client handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Handle a connected client
    async fn handle_client(
        client_id: String,
        stream: TcpStream,
        clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
        control_tx: mpsc::Sender<BouncerCommand>,
    ) -> Result<()> {
        
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();
        
        // Notify bouncer of attachment
        control_tx.send(BouncerCommand::ClientAttached(client_id.clone())).await?;
        
        // Read client commands
        while let Ok(Some(line)) = lines.next_line().await {
            debug!("Bouncer received from client: {}", line);
            
            // Parse IRC message
            if let Ok(msg) = line.parse::<IrcMessage>() {
                // Handle authentication if needed
                if !clients.read().await.get(&client_id).unwrap().authenticated {
                    if msg.command == "PASS" {
                        // Verify password
                        // TODO: Check against config
                        clients.write().await.get_mut(&client_id).unwrap().authenticated = true;
                    }
                    continue;
                }
                
                // Handle other commands
                match msg.command.as_str() {
                    "PRIVMSG" => {
                        // Forward to server
                        // TODO: Implement server forwarding
                    }
                    "JOIN" => {
                        // Forward to server
                        // TODO: Implement server forwarding
                    }
                    _ => {
                        // Handle other commands
                    }
                }
            }
        }
        
        // Client disconnected
        control_tx.send(BouncerCommand::ClientDetached(client_id.clone())).await?;
        clients.write().await.remove(&client_id);
        
        Ok(())
    }
    
    /// Add message to history
    async fn add_to_history(&self, target: &str, message: IrcMessage, sent_by_us: bool) {
        let mut history = self.history.write().await;
        let max_size = history.max_size; // Extract max_size before mutable borrow
        let entry = HistoryEntry {
            timestamp: Utc::now(),
            message,
            sent_by_us,
        };
        
        let target_history = history.targets.entry(target.to_string())
            .or_insert_with(VecDeque::new);
        
        target_history.push_back(entry);
        
        // Trim if exceeds max size
        while target_history.len() > max_size {
            target_history.pop_front();
        }
    }
    
    /// Get bouncer status
    pub async fn get_status(&self) -> BouncerStatus {
        let state = self.connection_state.read().await;
        let clients = self.clients.read().await;
        let history = self.history.read().await;
        
        BouncerStatus {
            state: "running".to_string(),
            uptime: 0, // TODO: Track uptime
            connected_clients: clients.len(),
            channels: state.channels.keys().cloned().collect(),
            history_size: history.targets.values()
                .map(|v| v.len()).sum(),
            last_activity: state.last_activity,
        }
    }
    
    /// Control loop for handling bouncer commands
    async fn control_loop(
        mut rx: mpsc::Receiver<BouncerCommand>,
        connection_state: Arc<RwLock<ConnectionState>>,
        history: Arc<RwLock<MessageHistory>>,
        clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                BouncerCommand::ClientAttached(id) => {
                    info!("Client {} attached to bouncer", id);
                    
                    // Send current state to client
                    // TODO: Implement state sync
                }
                BouncerCommand::ClientDetached(id) => {
                    info!("Client {} detached from bouncer", id);
                }
                BouncerCommand::ReplayHistory(client_id, target) => {
                    // TODO: Implement history replay
                }
                BouncerCommand::UpdateConfig(config) => {
                    // TODO: Implement config update
                }
                BouncerCommand::GetStatus(tx) => {
                    let state = connection_state.read().await;
                    let status = BouncerStatus {
                        state: "running".to_string(),
                        uptime: 0, // TODO: Track uptime
                        connected_clients: clients.read().await.len(),
                        channels: state.channels.keys().cloned().collect(),
                        history_size: history.read().await.targets.values()
                            .map(|v| v.len()).sum(),
                        last_activity: state.last_activity,
                    };
                    let _ = tx.send(status).await;
                }
            }
        }
    }
}