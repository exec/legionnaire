//! Plugin system for Legionnaire
//! 
//! Provides a flexible plugin architecture for extending the IRC client with
//! additional functionality like E2EE protocols, custom commands, notifications, etc.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use legion_protocol::IrcMessage;
use crate::client::IrcConfig;
use anyhow::Result;

pub mod manager;
pub mod e2ee;
pub mod weather_bot;

pub use manager::PluginManager;
pub use e2ee::E2eePlugin;
pub use weather_bot::WeatherBotPlugin;

/// Plugin lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// Plugin is loaded but not started
    Loaded,
    /// Plugin is running
    Running,
    /// Plugin is stopped
    Stopped,
    /// Plugin encountered an error
    Error,
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Unique plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Required capabilities
    pub capabilities: Vec<String>,
}

/// Plugin configuration
pub type PluginConfig = serde_json::Value;

/// Plugin context provided to plugins
#[derive(Clone)]
pub struct PluginContext {
    /// Client configuration
    pub client_config: Arc<IrcConfig>,
    /// Plugin-specific configuration
    pub plugin_config: PluginConfig,
    /// Shared state storage
    pub shared_state: Arc<RwLock<HashMap<String, Box<dyn Any + Send + Sync>>>>,
}

/// Core plugin trait that all plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn info(&self) -> PluginInfo;
    
    /// Initialize the plugin
    async fn init(&mut self, context: PluginContext) -> Result<()>;
    
    /// Start the plugin
    async fn start(&mut self) -> Result<()>;
    
    /// Stop the plugin
    async fn stop(&mut self) -> Result<()>;
    
    /// Handle incoming IRC messages
    async fn handle_message(&mut self, message: &IrcMessage) -> Result<()>;
    
    /// Handle outgoing IRC messages (can modify or block)
    async fn filter_outgoing(&mut self, message: &mut IrcMessage) -> Result<bool>;
    
    /// Get plugin state
    fn state(&self) -> PluginState;
    
    /// Plugin-specific commands
    async fn handle_command(&mut self, command: &str, args: &[String]) -> Result<String>;
}

/// Plugin hook points
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPoint {
    /// Before connection is established
    PreConnect,
    /// After connection is established
    PostConnect,
    /// Before disconnection
    PreDisconnect,
    /// After disconnection
    PostDisconnect,
    /// Before message is sent
    PreSend,
    /// After message is sent
    PostSend,
    /// Before message is processed
    PreReceive,
    /// After message is processed
    PostReceive,
    /// On authentication
    OnAuth,
    /// On join channel
    OnJoin,
    /// On part channel
    OnPart,
    /// On mode change
    OnMode,
}

/// Hook function type
pub type HookFn = Arc<dyn Fn(&IrcMessage) -> Result<()> + Send + Sync>;

/// Extended plugin trait for plugins that need hook functionality
#[async_trait]
pub trait HookablePlugin: Plugin {
    /// Register hooks for specific points
    fn hooks(&self) -> HashMap<HookPoint, Vec<HookFn>> {
        HashMap::new()
    }
}

/// Plugin factory function type
pub type PluginFactory = Box<dyn Fn() -> Box<dyn Plugin> + Send + Sync>;

/// Plugin registry for dynamic plugin loading
pub struct PluginRegistry {
    factories: HashMap<String, PluginFactory>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        let mut registry = Self {
            factories: HashMap::new(),
        };
        
        // Register built-in plugins
        registry.register_builtin_plugins();
        
        registry
    }
    
    /// Register built-in plugins
    fn register_builtin_plugins(&mut self) {
        // Register E2EE plugin
        self.register("e2ee", Box::new(|| Box::new(crate::plugin::E2eePlugin::new())));
        
        // Register Weather Bot plugin
        self.register("weather-bot", Box::new(|| Box::new(crate::plugin::WeatherBotPlugin::new())));
    }
    
    /// Register a plugin factory
    pub fn register(&mut self, name: &str, factory: PluginFactory) {
        self.factories.insert(name.to_string(), factory);
    }
    
    /// Create a plugin instance
    pub fn create(&self, name: &str) -> Option<Box<dyn Plugin>> {
        self.factories.get(name).map(|factory| factory())
    }
    
    /// List available plugins
    pub fn list(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}