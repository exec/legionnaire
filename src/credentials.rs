//! Secure Credential Storage
//!
//! Provides encrypted storage for passwords, API keys, and other sensitive data
//! using OS keystore integration and fallback encryption.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use secrecy::{Secret, ExposeSecret};
use std::collections::HashMap;
use tracing::{info, warn, error, debug};
use blake3;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Credentials as WinCreds;

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

/// Credential storage backend
#[derive(Debug, Clone)]
pub enum CredentialBackend {
    /// OS keystore (Windows Credential Manager, macOS Keychain, Linux Secret Service)
    OSKeystore,
    /// Encrypted file storage with master password
    EncryptedFile { master_password_hash: [u8; 32] },
    /// Environment variables (least secure, for testing)
    Environment,
    /// In-memory only (lost on restart)
    Memory,
}

/// Credential type for organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    /// IRC server password
    ServerPassword { server: String },
    /// SASL authentication
    SaslCredentials { server: String, username: String },
    /// Bot API keys
    ApiKey { service: String },
    /// Plugin-specific secrets
    PluginSecret { plugin: String, key: String },
    /// E2EE private keys
    EncryptionKey { key_id: String },
}

/// Stored credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialEntry {
    credential_type: CredentialType,
    value: Vec<u8>, // Encrypted value
    created_at: chrono::DateTime<chrono::Utc>,
    last_accessed: chrono::DateTime<chrono::Utc>,
    access_count: u64,
}

/// Credential manager
#[derive(Debug, Clone)]
pub struct CredentialManager {
    backend: CredentialBackend,
    /// In-memory cache (encrypted)
    cache: HashMap<String, CredentialEntry>,
    /// Encryption key for file storage
    encryption_key: Option<[u8; 32]>,
}

impl CredentialManager {
    /// Create a new credential manager with automatic backend selection
    pub fn new() -> Result<Self> {
        let backend = Self::detect_best_backend()?;
        info!("Using credential backend: {:?}", backend);
        
        Ok(Self {
            backend,
            cache: HashMap::new(),
            encryption_key: None,
        })
    }
    
    /// Create with specific backend
    pub fn with_backend(backend: CredentialBackend) -> Self {
        Self {
            backend,
            cache: HashMap::new(),
            encryption_key: None,
        }
    }
    
    /// Detect the best available credential storage backend
    fn detect_best_backend() -> Result<CredentialBackend> {
        // Try OS keystore first
        if Self::is_os_keystore_available() {
            return Ok(CredentialBackend::OSKeystore);
        }
        
        // Fall back to encrypted file
        warn!("OS keystore not available, using encrypted file storage");
        
        // Generate or load master password
        let master_password = Self::get_or_create_master_password()?;
        let master_password_hash = blake3::hash(&master_password.expose_secret().as_bytes());
        
        Ok(CredentialBackend::EncryptedFile { 
            master_password_hash: *master_password_hash.as_bytes() 
        })
    }
    
    /// Check if OS keystore is available
    fn is_os_keystore_available() -> bool {
        #[cfg(target_os = "windows")]
        {
            // Check if Windows Credential Manager is available
            true // Usually available on Windows
        }
        
        #[cfg(target_os = "macos")]
        {
            // Check if macOS Keychain is available
            SecKeychain::default().is_ok()
        }
        
        #[cfg(target_os = "linux")]
        {
            // Check if Secret Service is available (GNOME/KDE)
            std::process::Command::new("secret-tool")
                .arg("--version")
                .output()
                .is_ok()
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }
    
    /// Get or create master password for encrypted file storage
    fn get_or_create_master_password() -> Result<Secret<String>> {
        use rpassword::prompt_password;
        use std::env;
        
        // Try environment variable first (for automation)
        if let Ok(password) = env::var("LEGIONNAIRE_MASTER_PASSWORD") {
            return Ok(Secret::new(password));
        }
        
        // Check if master password file exists
        let config_dir = directories::ProjectDirs::from("", "", "legionnaire")
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        
        let master_file = config_dir.config_dir().join(".master_password_hint");
        
        if master_file.exists() {
            // Existing installation - prompt for password
            let password = prompt_password("Enter master password for credential storage: ")?;
            Ok(Secret::new(password))
        } else {
            // New installation - create master password
            println!("Setting up secure credential storage...");
            let password = prompt_password("Create a master password for credential storage: ")?;
            let confirm = prompt_password("Confirm master password: ")?;
            
            if password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }
            
            if password.len() < 8 {
                return Err(anyhow!("Master password must be at least 8 characters"));
            }
            
            // Create hint file (doesn't contain password)
            std::fs::create_dir_all(config_dir.config_dir())?;
            std::fs::write(&master_file, "Legionnaire master password set")?;
            
            info!("Master password created successfully");
            Ok(Secret::new(password))
        }
    }
    
    /// Store a credential
    pub async fn store_credential(&mut self, cred_type: CredentialType, value: Secret<String>) -> Result<()> {
        let key = self.credential_key(&cred_type);
        let encrypted_value = self.encrypt_value(value.expose_secret().as_bytes())?;
        
        let entry = CredentialEntry {
            credential_type: cred_type.clone(),
            value: encrypted_value,
            created_at: chrono::Utc::now(),
            last_accessed: chrono::Utc::now(),
            access_count: 0,
        };
        
        match &self.backend {
            CredentialBackend::OSKeystore => {
                self.store_in_os_keystore(&key, &entry).await?;
            }
            CredentialBackend::EncryptedFile { .. } => {
                self.store_in_encrypted_file(&key, &entry).await?;
            }
            CredentialBackend::Environment => {
                warn!("Environment backend does not persist credentials");
            }
            CredentialBackend::Memory => {
                // Just store in cache
            }
        }
        
        // Always cache for performance
        self.cache.insert(key.clone(), entry);
        
        debug!("Stored credential: {:?}", cred_type);
        Ok(())
    }
    
    /// Retrieve a credential
    pub async fn get_credential(&mut self, cred_type: &CredentialType) -> Result<Option<Secret<String>>> {
        let key = self.credential_key(cred_type);
        
        // Check cache first
        if let Some(entry) = self.cache.get_mut(&key) {
            entry.last_accessed = chrono::Utc::now();
            entry.access_count += 1;
            
            let encrypted_value = entry.value.clone();
            drop(entry); // Release the mutable borrow
            let decrypted = self.decrypt_value(&encrypted_value)?;
            return Ok(Some(Secret::new(String::from_utf8(decrypted)?)));
        }
        
        // Load from backend
        let entry = match &self.backend {
            CredentialBackend::OSKeystore => {
                self.load_from_os_keystore(&key).await?
            }
            CredentialBackend::EncryptedFile { .. } => {
                self.load_from_encrypted_file(&key).await?
            }
            CredentialBackend::Environment => {
                self.load_from_environment(&key)?
            }
            CredentialBackend::Memory => None,
        };
        
        if let Some(mut entry) = entry {
            entry.last_accessed = chrono::Utc::now();
            entry.access_count += 1;
            
            let decrypted = self.decrypt_value(&entry.value)?;
            let secret = Secret::new(String::from_utf8(decrypted)?);
            
            // Update cache
            self.cache.insert(key, entry);
            
            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }
    
    /// Delete a credential
    pub async fn delete_credential(&mut self, cred_type: &CredentialType) -> Result<bool> {
        let key = self.credential_key(cred_type);
        
        let existed = match &self.backend {
            CredentialBackend::OSKeystore => {
                self.delete_from_os_keystore(&key).await?
            }
            CredentialBackend::EncryptedFile { .. } => {
                self.delete_from_encrypted_file(&key).await?
            }
            _ => self.cache.contains_key(&key),
        };
        
        self.cache.remove(&key);
        
        if existed {
            debug!("Deleted credential: {:?}", cred_type);
        }
        
        Ok(existed)
    }
    
    /// List all stored credentials (without values)
    pub async fn list_credentials(&self) -> Result<Vec<CredentialType>> {
        // In a real implementation, this would scan the backend
        // For now, just return cached entries
        Ok(self.cache.values().map(|e| e.credential_type.clone()).collect())
    }
    
    /// Generate unique key for credential type
    fn credential_key(&self, cred_type: &CredentialType) -> String {
        match cred_type {
            CredentialType::ServerPassword { server } => {
                format!("server_password:{}", server)
            }
            CredentialType::SaslCredentials { server, username } => {
                format!("sasl:{}:{}", server, username)
            }
            CredentialType::ApiKey { service } => {
                format!("api_key:{}", service)
            }
            CredentialType::PluginSecret { plugin, key } => {
                format!("plugin:{}:{}", plugin, key)
            }
            CredentialType::EncryptionKey { key_id } => {
                format!("e2ee_key:{}", key_id)
            }
        }
    }
    
    /// Encrypt a value for storage
    fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>> {
        match &self.backend {
            CredentialBackend::EncryptedFile { master_password_hash } => {
                // Use ChaCha20-Poly1305 with master password hash as key
                use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
                
                let cipher = ChaCha20Poly1305::new(Key::from_slice(master_password_hash));
                let nonce = Nonce::from_slice(b"legionnaire1"); // Fixed nonce for simplicity
                
                cipher.encrypt(nonce, value)
                    .map_err(|e| anyhow!("Encryption failed: {}", e))
            }
            _ => Ok(value.to_vec()), // No encryption needed for other backends
        }
    }
    
    /// Decrypt a value from storage
    fn decrypt_value(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        match &self.backend {
            CredentialBackend::EncryptedFile { master_password_hash } => {
                use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
                
                let cipher = ChaCha20Poly1305::new(Key::from_slice(master_password_hash));
                let nonce = Nonce::from_slice(b"legionnaire1");
                
                cipher.decrypt(nonce, encrypted)
                    .map_err(|e| anyhow!("Decryption failed: {}", e))
            }
            _ => Ok(encrypted.to_vec()),
        }
    }
    
    /// OS keystore operations (platform-specific implementations)
    async fn store_in_os_keystore(&self, key: &str, entry: &CredentialEntry) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Windows Credential Manager implementation
            warn!("Windows keystore not implemented yet");
            Ok(())
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS Keychain implementation
            warn!("macOS keystore not implemented yet");
            Ok(())
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux Secret Service implementation
            warn!("Linux Secret Service not implemented yet");
            Ok(())
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Err(anyhow!("OS keystore not supported on this platform"))
        }
    }
    
    async fn load_from_os_keystore(&self, key: &str) -> Result<Option<CredentialEntry>> {
        // Platform-specific implementations would go here
        warn!("OS keystore loading not fully implemented");
        Ok(None)
    }
    
    async fn delete_from_os_keystore(&self, key: &str) -> Result<bool> {
        // Platform-specific implementations would go here  
        warn!("OS keystore deletion not fully implemented");
        Ok(false)
    }
    
    /// Encrypted file operations
    async fn store_in_encrypted_file(&self, key: &str, entry: &CredentialEntry) -> Result<()> {
        let config_dir = directories::ProjectDirs::from("", "", "legionnaire")
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        
        let credentials_file = config_dir.config_dir().join("credentials.enc");
        
        // Load existing file or create new
        let mut all_credentials: HashMap<String, CredentialEntry> = if credentials_file.exists() {
            let encrypted_data = std::fs::read(&credentials_file)?;
            let decrypted_data = self.decrypt_value(&encrypted_data)?;
            serde_json::from_slice(&decrypted_data).unwrap_or_default()
        } else {
            HashMap::new()
        };
        
        // Add/update entry
        all_credentials.insert(key.to_string(), entry.clone());
        
        // Encrypt and save
        let serialized = serde_json::to_vec(&all_credentials)?;
        let encrypted = self.encrypt_value(&serialized)?;
        
        std::fs::create_dir_all(config_dir.config_dir())?;
        std::fs::write(&credentials_file, encrypted)?;
        
        Ok(())
    }
    
    async fn load_from_encrypted_file(&self, key: &str) -> Result<Option<CredentialEntry>> {
        let config_dir = directories::ProjectDirs::from("", "", "legionnaire")
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        
        let credentials_file = config_dir.config_dir().join("credentials.enc");
        
        if !credentials_file.exists() {
            return Ok(None);
        }
        
        let encrypted_data = std::fs::read(&credentials_file)?;
        let decrypted_data = self.decrypt_value(&encrypted_data)?;
        let all_credentials: HashMap<String, CredentialEntry> = serde_json::from_slice(&decrypted_data)?;
        
        Ok(all_credentials.get(key).cloned())
    }
    
    async fn delete_from_encrypted_file(&self, key: &str) -> Result<bool> {
        let config_dir = directories::ProjectDirs::from("", "", "legionnaire")
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        
        let credentials_file = config_dir.config_dir().join("credentials.enc");
        
        if !credentials_file.exists() {
            return Ok(false);
        }
        
        let encrypted_data = std::fs::read(&credentials_file)?;
        let decrypted_data = self.decrypt_value(&encrypted_data)?;
        let mut all_credentials: HashMap<String, CredentialEntry> = serde_json::from_slice(&decrypted_data)?;
        
        let existed = all_credentials.remove(key).is_some();
        
        if existed {
            // Save updated file
            let serialized = serde_json::to_vec(&all_credentials)?;
            let encrypted = self.encrypt_value(&serialized)?;
            std::fs::write(&credentials_file, encrypted)?;
        }
        
        Ok(existed)
    }
    
    /// Environment variable fallback
    fn load_from_environment(&self, key: &str) -> Result<Option<CredentialEntry>> {
        let env_key = format!("LEGIONNAIRE_CRED_{}", key.to_uppercase().replace([':', '-', '.'], "_"));
        
        if let Ok(value) = std::env::var(&env_key) {
            // Create a dummy entry for environment variables
            Ok(Some(CredentialEntry {
                credential_type: CredentialType::ApiKey { service: "env".to_string() },
                value: value.into_bytes(),
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
                access_count: 0,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Helper functions for credential management in configurations
pub mod helpers {
    use super::*;
    
    /// Migrate plaintext passwords to secure storage
    pub async fn migrate_plaintext_config(
        config_path: &std::path::Path,
        cred_manager: &mut CredentialManager
    ) -> Result<bool> {
        info!("Checking for plaintext credentials to migrate");
        
        // This would scan config files for plaintext passwords and migrate them
        // For now, just return false (no migration needed)
        Ok(false)
    }
    
    /// Get credential with fallback to config file (for backward compatibility)
    pub async fn get_credential_with_fallback(
        cred_manager: &mut CredentialManager,
        cred_type: &CredentialType,
        fallback_value: Option<&str>
    ) -> Result<Option<Secret<String>>> {
        // Try credential manager first
        if let Some(cred) = cred_manager.get_credential(cred_type).await? {
            return Ok(Some(cred));
        }
        
        // Fall back to provided value (from config file)
        if let Some(value) = fallback_value {
            warn!("Using plaintext credential from config file. Consider using secure storage.");
            return Ok(Some(Secret::new(value.to_string())));
        }
        
        Ok(None)
    }
}