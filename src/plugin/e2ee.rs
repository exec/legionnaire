//! End-to-End Encryption Plugin
//! 
//! Provides E2EE capabilities using the Phalanx protocol for secure messaging.
//! Intercepts PRIVMSG commands and transparently encrypts/decrypts messages.

use super::{Plugin, PluginInfo, PluginState, PluginContext};
use async_trait::async_trait;
use legion_protocol::IrcMessage;
use phalanx::{PhalanxGroup, Identity, MessageContent};
use bytes::Bytes;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

/// E2EE Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eeConfig {
    /// Enable automatic encryption for all messages
    pub auto_encrypt: bool,
    /// Enable E2EE for specific channels/users
    pub encrypt_targets: Vec<String>,
    /// Key exchange timeout in seconds
    pub key_exchange_timeout: u64,
    /// Enable forward secrecy with key rotation
    pub forward_secrecy: bool,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
}

impl Default for E2eeConfig {
    fn default() -> Self {
        Self {
            auto_encrypt: false,
            encrypt_targets: Vec::new(),
            key_exchange_timeout: 30,
            forward_secrecy: true,
            key_rotation_interval: 3600, // 1 hour
        }
    }
}

/// E2EE Plugin state
pub struct E2eePlugin {
    state: PluginState,
    config: E2eeConfig,
    /// Local identity for encryption
    identity: Arc<RwLock<Option<Identity>>>,
    /// Active encrypted groups/conversations
    groups: Arc<RwLock<HashMap<String, Arc<RwLock<PhalanxGroup>>>>>,
    /// Pending key exchanges
    pending_exchanges: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl E2eePlugin {
    pub fn new() -> Self {
        Self {
            state: PluginState::Loaded,
            config: E2eeConfig::default(),
            identity: Arc::new(RwLock::new(None)),
            groups: Arc::new(RwLock::new(HashMap::new())),
            pending_exchanges: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Initialize identity if not already done
    async fn ensure_identity(&self) -> Result<()> {
        let mut identity_guard = self.identity.write().await;
        if identity_guard.is_none() {
            info!("Generating new E2EE identity");
            let identity = Identity::generate();
            *identity_guard = Some(identity);
        }
        Ok(())
    }
    
    /// Check if target should be encrypted
    async fn should_encrypt(&self, target: &str) -> bool {
        self.config.auto_encrypt || self.config.encrypt_targets.contains(&target.to_string())
    }
    
    /// Get or create encrypted group for target
    async fn get_or_create_group(&self, target: &str) -> Result<Arc<RwLock<PhalanxGroup>>> {
        let mut groups = self.groups.write().await;
        
        if let Some(group) = groups.get(target) {
            return Ok(Arc::clone(group));
        }
        
        // Create new group
        self.ensure_identity().await?;
        let identity_guard = self.identity.read().await;
        let identity = identity_guard.as_ref().unwrap().clone();
        
        let group = Arc::new(RwLock::new(PhalanxGroup::new(identity)));
        
        groups.insert(target.to_string(), Arc::clone(&group));
        info!("Created new E2EE group for target: {}", target);
        
        Ok(group)
    }
    
    /// Encrypt a message for target
    async fn encrypt_message(&self, target: &str, message: &str) -> Result<String> {
        let group_arc = self.get_or_create_group(target).await?;
        let mut group = group_arc.write().await;
        
        self.ensure_identity().await?;
        
        // Create message content
        let content = MessageContent {
            data: Bytes::from(message.as_bytes().to_vec()),
            reply_to: None,
            thread_id: None,
            metadata: std::collections::HashMap::new(),
        };
        
        let encrypted = group.encrypt_message(&content)?;
        
        // Serialize with serde_json
        let serialized = serde_json::to_vec(&encrypted)?;
        let encoded = base64::encode(&serialized);
        
        // Prefix with E2EE marker
        Ok(format!("[E2EE] {}", encoded))
    }
    
    /// Decrypt a message from target
    async fn decrypt_message(&self, target: &str, encrypted_message: &str) -> Result<String> {
        // Check if message is E2EE encrypted
        if !encrypted_message.starts_with("[E2EE] ") {
            return Ok(encrypted_message.to_string()); // Not encrypted
        }
        
        let encoded = &encrypted_message[7..]; // Remove "[E2EE] " prefix
        let serialized = base64::decode(encoded)
            .map_err(|e| anyhow!("Failed to decode E2EE message: {}", e))?;
        
        // Parse GroupMessage from JSON
        let group_message: phalanx::message::GroupMessage = serde_json::from_slice(&serialized)?;
        
        let groups = self.groups.read().await;
        let group_arc = groups.get(target)
            .ok_or_else(|| anyhow!("No E2EE group found for target: {}", target))?;
        
        let group = group_arc.read().await;
        let content = group.decrypt_message(&group_message)?;
        let message = String::from_utf8(content.data.to_vec())
            .map_err(|e| anyhow!("Failed to decode decrypted message: {}", e))?;
        
        Ok(message)
    }
    
    /// Handle key exchange handshake
    async fn handle_handshake(&self, from: &str, payload: &str) -> Result<()> {
        info!("Handling E2EE handshake from: {}", from);
        
        // TODO: Implement proper handshake protocol
        // For now, just acknowledge
        
        Ok(())
    }
    
    /// Start key exchange with target
    async fn start_key_exchange(&self, target: &str) -> Result<()> {
        info!("Starting E2EE key exchange with: {}", target);
        
        self.ensure_identity().await?;
        let identity_guard = self.identity.read().await;
        let identity = identity_guard.as_ref().unwrap();
        
        // TODO: Create and send handshake message
        // This would typically involve:
        // 1. Generate ephemeral key
        // 2. Create handshake payload
        // 3. Send via NOTICE or PRIVMSG
        
        let mut pending = self.pending_exchanges.write().await;
        pending.insert(target.to_string(), chrono::Utc::now());
        
        Ok(())
    }
    
    /// Clean up expired key exchanges
    async fn cleanup_expired_exchanges(&self) {
        let mut pending = self.pending_exchanges.write().await;
        let now = chrono::Utc::now();
        let timeout = chrono::Duration::seconds(self.config.key_exchange_timeout as i64);
        
        pending.retain(|target, started_at| {
            if now.signed_duration_since(*started_at) > timeout {
                warn!("Key exchange with {} timed out", target);
                false
            } else {
                true
            }
        });
    }
}

#[async_trait]
impl Plugin for E2eePlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "e2ee".to_string(),
            version: "0.1.0".to_string(),
            description: "End-to-end encryption using Phalanx protocol".to_string(),
            author: "Legion Protocol Contributors".to_string(),
            capabilities: vec!["legion-protocol".to_string(), "e2ee".to_string()],
        }
    }
    
    async fn init(&mut self, context: PluginContext) -> Result<()> {
        // Load configuration from context
        if let Ok(config) = serde_json::from_value::<E2eeConfig>(context.plugin_config) {
            self.config = config;
            info!("E2EE plugin configured with {} encrypted targets", self.config.encrypt_targets.len());
        }
        
        // Initialize identity
        self.ensure_identity().await?;
        
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        self.state = PluginState::Running;
        info!("E2EE plugin started successfully");
        
        // Start cleanup task for expired key exchanges
        let pending_exchanges = Arc::clone(&self.pending_exchanges);
        let timeout = self.config.key_exchange_timeout;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(timeout / 2));
            
            loop {
                interval.tick().await;
                
                // Clean up expired exchanges
                let mut pending = pending_exchanges.write().await;
                let now = chrono::Utc::now();
                let timeout_duration = chrono::Duration::seconds(timeout as i64);
                
                pending.retain(|target, started_at| {
                    if now.signed_duration_since(*started_at) > timeout_duration {
                        debug!("Cleaned up expired key exchange with {}", target);
                        false
                    } else {
                        true
                    }
                });
            }
        });
        
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.state = PluginState::Stopped;
        info!("E2EE plugin stopped");
        Ok(())
    }
    
    async fn handle_message(&mut self, message: &IrcMessage) -> Result<()> {
        match message.command.as_str() {
            "PRIVMSG" | "NOTICE" => {
                if let Some(target) = message.params.get(0) {
                    if let Some(text) = message.params.get(1) {
                        // Check if this is an E2EE handshake
                        if text.starts_with("[HANDSHAKE]") {
                            if let Some(from) = &message.prefix {
                                let nick = from.split('!').next().unwrap_or(from);
                                self.handle_handshake(nick, text).await?;
                            }
                        }
                        // Check if this is an encrypted message
                        else if text.starts_with("[E2EE]") {
                            debug!("Received encrypted message from {} to {}", 
                                   message.prefix.as_deref().unwrap_or("unknown"), target);
                            
                            // Decrypt and log (in real implementation, would replace in message)
                            if let Ok(decrypted) = self.decrypt_message(target, text).await {
                                info!("Decrypted message: {}", decrypted);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    async fn filter_outgoing(&mut self, message: &mut IrcMessage) -> Result<bool> {
        match message.command.as_str() {
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    let target = message.params[0].clone();
                    let text = message.params[1].clone();
                    
                    // Check if we should encrypt this message
                    if self.should_encrypt(&target).await {
                        match self.encrypt_message(&target, &text).await {
                            Ok(encrypted) => {
                                // Replace the message text with encrypted version
                                message.params[1] = encrypted;
                                debug!("Encrypted outgoing message to {}", target);
                            }
                            Err(e) => {
                                warn!("Failed to encrypt message to {}: {}", target, e);
                                // Continue with unencrypted message
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(true) // Always allow the message to be sent
    }
    
    fn state(&self) -> PluginState {
        self.state
    }
    
    async fn handle_command(&mut self, command: &str, args: &[String]) -> Result<String> {
        match command {
            "status" => {
                let groups = self.groups.read().await;
                let pending = self.pending_exchanges.read().await;
                
                Ok(format!(
                    "E2EE Plugin Status:\\n\\\
                     State: {:?}\\n\\\
                     Active groups: {}\\n\\\
                     Pending exchanges: {}\\n\\\
                     Auto-encrypt: {}\\n\\\
                     Encrypted targets: {}",
                    self.state,
                    groups.len(),
                    pending.len(),
                    self.config.auto_encrypt,
                    self.config.encrypt_targets.join(", ")
                ))
            }
            
            "encrypt" => {
                if args.is_empty() {
                    return Ok("Usage: encrypt <target>".to_string());
                }
                
                let target = &args[0];
                if !self.config.encrypt_targets.contains(target) {
                    self.config.encrypt_targets.push(target.clone());
                    // Start key exchange
                    self.start_key_exchange(target).await?;
                    Ok(format!("Started E2EE for target: {}", target))
                } else {
                    Ok(format!("E2EE already enabled for: {}", target))
                }
            }
            
            "decrypt" => {
                if args.is_empty() {
                    return Ok("Usage: decrypt <target>".to_string());
                }
                
                let target = &args[0];
                self.config.encrypt_targets.retain(|t| t != target);
                Ok(format!("Disabled E2EE for target: {}", target))
            }
            
            "groups" => {
                let groups = self.groups.read().await;
                let mut output = format!("Active E2EE groups ({}):\\n", groups.len());
                
                for (target, _group) in groups.iter() {
                    output.push_str(&format!("  {}\\n", target));
                }
                
                Ok(output)
            }
            
            _ => Ok(format!("Unknown E2EE command: {}. Available: status, encrypt, decrypt, groups", command))
        }
    }
}