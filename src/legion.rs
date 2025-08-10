//! Legion Protocol client support
//! 
//! Provides Legion Protocol encrypted channel support and Phalanx integration.

use crate::error::{IronError, Result};
use legion_protocol::{IrcMessage, Capability, Command};
use phalanx::{Identity, async_group::AsyncPhalanxGroup, message::MessageContent};
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};
use base64;

/// Legion Protocol client manager
pub struct LegionClient {
    /// Client identity for Legion Protocol
    identity: Identity,
    /// Active encrypted channels
    encrypted_channels: RwLock<HashMap<String, AsyncPhalanxGroup>>,
    /// Legion Protocol capabilities
    capabilities: Vec<Capability>,
}

/// Configuration for Legion Protocol client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegionConfig {
    /// Enable Legion Protocol support
    pub enabled: bool,
    /// Auto-join encrypted channels
    pub auto_join_encrypted: bool,
    /// Identity storage path
    pub identity_path: Option<String>,
    /// Backup storage configuration
    pub backup_storage: Option<BackupConfig>,
    /// Channel-specific settings
    pub channel_settings: HashMap<String, ChannelConfig>,
}

/// Backup configuration for encrypted channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup storage type
    pub storage_type: String,
    /// Storage-specific configuration
    pub config: HashMap<String, String>,
}

/// Per-channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Auto-join this channel
    pub auto_join: bool,
    /// Enable key rotation
    pub key_rotation: bool,
    /// Member invitation policy
    pub invite_policy: InvitePolicy,
}

/// Channel invitation policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvitePolicy {
    /// Anyone can invite
    Open,
    /// Only channel operators can invite
    Restricted,
    /// Only specific roles can invite
    RoleRestricted(Vec<String>),
}

/// Legion Protocol channel events
#[derive(Debug, Clone)]
pub enum LegionEvent {
    /// Channel encryption established
    ChannelEncrypted { channel: String },
    /// Member joined encrypted channel
    MemberJoined { channel: String, member: String },
    /// Member left encrypted channel  
    MemberLeft { channel: String, member: String },
    /// Key rotation occurred
    KeyRotation { channel: String, sequence: u64 },
    /// Encrypted message received
    EncryptedMessage { channel: String, sender: String, content: String },
    /// Invitation received
    InvitationReceived { channel: String, inviter: String },
}

impl Default for LegionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_join_encrypted: false,
            identity_path: None,
            backup_storage: None,
            channel_settings: HashMap::new(),
        }
    }
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            auto_join: false,
            key_rotation: true,
            invite_policy: InvitePolicy::Restricted,
        }
    }
}

impl LegionClient {
    /// Create a new Legion Protocol client
    pub async fn new(config: LegionConfig) -> Result<Self> {
        let identity = if let Some(ref path) = config.identity_path {
            Self::load_or_generate_identity(path).await?
        } else {
            Identity::generate()
        };
        
        info!("Initialized Legion Protocol client with identity: {:?}", identity.public_key().id());
        
        Ok(Self {
            identity,
            encrypted_channels: RwLock::new(HashMap::new()),
            capabilities: vec![
                Capability::LegionProtocolV1,
            ],
        })
    }
    
    /// Get client identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    
    /// Get supported Legion Protocol capabilities
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
    
    /// Check if a channel is Legion encrypted
    pub fn is_encrypted_channel(&self, channel: &str) -> bool {
        // Legion encrypted channels start with '!'
        channel.starts_with('!')
    }
    
    /// Join an encrypted channel
    pub async fn join_encrypted_channel(&self, channel: &str) -> Result<()> {
        if !self.is_encrypted_channel(channel) {
            return Err(IronError::Configuration("Not a Legion encrypted channel".to_string()));
        }
        
        debug!("Joining encrypted channel: {}", channel);
        
        // Create Phalanx group for this channel
        let group = AsyncPhalanxGroup::new(self.identity.clone());
        
        // Store the encrypted channel
        let mut channels = self.encrypted_channels.write().await;
        channels.insert(channel.to_string(), group);
        
        info!("Successfully joined encrypted channel: {}", channel);
        Ok(())
    }
    
    /// Leave an encrypted channel
    pub async fn leave_encrypted_channel(&self, channel: &str) -> Result<()> {
        let mut channels = self.encrypted_channels.write().await;
        if let Some(_group) = channels.remove(channel) {
            info!("Left encrypted channel: {}", channel);
            Ok(())
        } else {
            Err(IronError::Configuration(format!("Not in encrypted channel: {}", channel)))
        }
    }
    
    /// Send encrypted message to a channel
    pub async fn send_encrypted_message(&self, channel: &str, message: &str) -> Result<String> {
        let channels = self.encrypted_channels.read().await;
        if let Some(group) = channels.get(channel) {
            let message_content = MessageContent::text(message.to_string());
            let encrypted_message = group.encrypt_message(&message_content).await
                .map_err(|e| IronError::Configuration(format!("Encryption failed: {}", e)))?;
            
            // Serialize encrypted message to base64 for IRC transmission
            let serialized = serde_json::to_string(&encrypted_message)
                .map_err(|e| IronError::Configuration(format!("Message serialization failed: {}", e)))?;
            
            debug!("Encrypted message for channel {}: {} chars", channel, serialized.len());
            Ok(base64::encode(&serialized))
        } else {
            Err(IronError::Configuration(format!("Not in encrypted channel: {}", channel)))
        }
    }
    
    /// Decrypt received message from a channel
    pub async fn decrypt_message(&self, channel: &str, encrypted_data: &str) -> Result<String> {
        let channels = self.encrypted_channels.read().await;
        if let Some(group) = channels.get(channel) {
            // Decode from base64 and deserialize
            let decoded = base64::decode(&encrypted_data)
                .map_err(|e| IronError::Parse(format!("Invalid base64 in encrypted message: {}", e)))?;
            
            let encrypted_message = serde_json::from_slice(&decoded)
                .map_err(|e| IronError::Parse(format!("Invalid encrypted message format: {}", e)))?;
            
            let decrypted_content = group.decrypt_message(&encrypted_message).await
                .map_err(|e| IronError::Configuration(format!("Decryption failed: {}", e)))?;
            
            let message = decrypted_content.as_string()
                .map_err(|e| IronError::Parse(format!("Failed to decode decrypted text: {}", e)))?;
            
            debug!("Decrypted message from channel {}: {} chars", channel, message.len());
            Ok(message.clone())
        } else {
            Err(IronError::Configuration(format!("Not in encrypted channel: {}", channel)))
        }
    }
    
    /// Handle Legion Protocol messages
    pub async fn handle_legion_message(&self, message: &IrcMessage) -> Result<Option<LegionEvent>> {
        // Handle based on the parsed command structure
        match message.command.to_uppercase().as_str() {
            "JOIN" if !message.params.is_empty() => {
                let channel = &message.params[0];
                if self.is_encrypted_channel(channel) {
                    self.join_encrypted_channel(channel).await?;
                    return Ok(Some(LegionEvent::ChannelEncrypted { 
                        channel: channel.to_string()
                    }));
                }
                Ok(None)
            },
            "PART" if !message.params.is_empty() => {
                let channel = &message.params[0];
                if self.is_encrypted_channel(channel) {
                    self.leave_encrypted_channel(channel).await?;
                }
                Ok(None)
            },
            "PRIVMSG" if message.params.len() >= 2 => {
                let target = &message.params[0];
                let text = &message.params[1];
                
                if self.is_encrypted_channel(target) {
                    // Handle encrypted private message
                    if let Ok(decrypted) = self.decrypt_message(target, text).await {
                        let sender = message.prefix.as_ref()
                            .map(|p| p.clone())
                            .unwrap_or_else(|| "unknown".to_string());
                            
                        Ok(Some(LegionEvent::EncryptedMessage {
                            channel: target.to_string(),
                            sender,
                            content: decrypted,
                        }))
                    } else {
                        warn!("Failed to decrypt message in channel: {}", target);
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            _ => Ok(None),
        }
    }
    
    /// List active encrypted channels
    pub async fn list_encrypted_channels(&self) -> Vec<String> {
        let channels = self.encrypted_channels.read().await;
        channels.keys().cloned().collect()
    }
    
    /// Get channel member count for encrypted channel
    pub async fn get_channel_member_count(&self, channel: &str) -> Result<usize> {
        let channels = self.encrypted_channels.read().await;
        if let Some(group) = channels.get(channel) {
            Ok(group.members().await.len())
        } else {
            Err(IronError::Configuration(format!("Not in encrypted channel: {}", channel)))
        }
    }
    
    /// Rotate keys for an encrypted channel
    pub async fn rotate_channel_keys(&self, channel: &str) -> Result<()> {
        let channels = self.encrypted_channels.read().await;
        if let Some(group) = channels.get(channel) {
            group.rotate_keys().await
                .map_err(|e| IronError::Configuration(format!("Key rotation failed: {}", e)))?;
            
            info!("Rotated keys for encrypted channel: {}", channel);
            Ok(())
        } else {
            Err(IronError::Configuration(format!("Not in encrypted channel: {}", channel)))
        }
    }
    
    /// Generate Legion capability negotiation message
    pub fn generate_cap_message(&self) -> String {
        let cap_list = self.capabilities.iter()
            .map(|cap| format!("+{}", cap.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
        
        format!("CAP REQ :{}", cap_list)
    }
    
    /// Derive group ID from channel name
    fn derive_group_id(&self, channel: &str) -> [u8; 32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_CHANNEL_GROUP_ID_V1");
        hasher.update(channel.as_bytes());
        hasher.update(&self.identity.public_key().id());
        
        *hasher.finalize().as_bytes()
    }
    
    /// Load or generate identity from file
    async fn load_or_generate_identity(path: &str) -> Result<Identity> {
        use tokio::fs;
        
        match fs::read(path).await {
            Ok(data) => {
                Identity::from_bytes(&data)
                    .map_err(|e| IronError::Configuration(format!("Invalid identity file: {}", e)))
            },
            Err(_) => {
                // Generate new identity and save it
                let identity = Identity::generate();
                let data = identity.to_bytes();
                
                if let Err(e) = fs::write(path, data).await {
                    warn!("Failed to save identity to {}: {}", path, e);
                }
                
                Ok(identity)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_legion_client_creation() {
        let config = LegionConfig::default();
        let client = LegionClient::new(config).await.unwrap();
        
        assert!(!client.capabilities().is_empty());
        assert!(client.capabilities().contains(&Capability::LegionProtocolV1));
    }
    
    #[tokio::test]
    async fn test_encrypted_channel_detection() {
        let config = LegionConfig::default();
        let client = LegionClient::new(config).await.unwrap();
        
        assert!(client.is_encrypted_channel("!test"));
        assert!(!client.is_encrypted_channel("#test"));
        assert!(!client.is_encrypted_channel("&test"));
    }
    
    #[tokio::test]
    async fn test_join_leave_encrypted_channel() {
        let config = LegionConfig::default();
        let client = LegionClient::new(config).await.unwrap();
        
        // Join encrypted channel
        client.join_encrypted_channel("!test").await.unwrap();
        assert!(client.list_encrypted_channels().await.contains(&"!test".to_string()));
        
        // Leave encrypted channel
        client.leave_encrypted_channel("!test").await.unwrap();
        assert!(!client.list_encrypted_channels().await.contains(&"!test".to_string()));
    }
}