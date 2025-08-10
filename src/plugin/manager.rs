//! Plugin manager for loading, managing, and coordinating plugins

use super::{Plugin, PluginContext, PluginState, HookPoint, HookFn, PluginRegistry};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use tracing::{info, warn, error};

/// Manages all loaded plugins
pub struct PluginManager {
    /// Registry of available plugins
    registry: Arc<PluginRegistry>,
    /// Currently loaded plugins
    plugins: Arc<RwLock<HashMap<String, Box<dyn Plugin>>>>,
    /// Registered hooks
    hooks: Arc<RwLock<HashMap<HookPoint, Vec<(String, HookFn)>>>>,
    /// Plugin context
    context: PluginContext,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(context: PluginContext) -> Self {
        Self {
            registry: Arc::new(PluginRegistry::new()),
            plugins: Arc::new(RwLock::new(HashMap::new())),
            hooks: Arc::new(RwLock::new(HashMap::new())),
            context,
        }
    }
    
    /// Load a plugin by name
    pub async fn load_plugin(&self, name: &str, config: Option<serde_json::Value>) -> Result<()> {
        // Check if already loaded
        if self.plugins.read().await.contains_key(name) {
            return Err(anyhow!("Plugin '{}' is already loaded", name));
        }
        
        // Create plugin instance
        let mut plugin = self.registry.create(name)
            .ok_or_else(|| anyhow!("Plugin '{}' not found in registry", name))?;
        
        // Create plugin-specific context
        let mut plugin_context = self.context.clone();
        if let Some(config) = config {
            plugin_context.plugin_config = config;
        }
        
        // Initialize plugin
        plugin.init(plugin_context).await?;
        
        info!("Loaded plugin: {} v{}", plugin.info().name, plugin.info().version);
        
        // Store plugin
        self.plugins.write().await.insert(name.to_string(), plugin);
        
        Ok(())
    }
    
    /// Start a plugin
    pub async fn start_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins.get_mut(name)
            .ok_or_else(|| anyhow!("Plugin '{}' not loaded", name))?;
        
        if plugin.state() == PluginState::Running {
            return Ok(());
        }
        
        plugin.start().await?;
        info!("Started plugin: {}", name);
        
        Ok(())
    }
    
    /// Stop a plugin
    pub async fn stop_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins.get_mut(name)
            .ok_or_else(|| anyhow!("Plugin '{}' not loaded", name))?;
        
        if plugin.state() == PluginState::Stopped {
            return Ok(());
        }
        
        plugin.stop().await?;
        info!("Stopped plugin: {}", name);
        
        Ok(())
    }
    
    /// Unload a plugin
    pub async fn unload_plugin(&self, name: &str) -> Result<()> {
        // Stop if running
        if let Err(e) = self.stop_plugin(name).await {
            warn!("Error stopping plugin before unload: {}", e);
        }
        
        // Remove from loaded plugins
        self.plugins.write().await.remove(name);
        
        // Remove hooks
        let mut hooks = self.hooks.write().await;
        for (_, hook_list) in hooks.iter_mut() {
            hook_list.retain(|(plugin_name, _)| plugin_name != name);
        }
        
        info!("Unloaded plugin: {}", name);
        Ok(())
    }
    
    /// Handle incoming IRC message through all plugins
    pub async fn handle_message(&self, message: &IrcMessage) -> Result<()> {
        // Run pre-receive hooks
        self.run_hooks(HookPoint::PreReceive, message).await?;
        
        // Let each plugin handle the message
        let mut plugins = self.plugins.write().await;
        for (name, plugin) in plugins.iter_mut() {
            if plugin.state() == PluginState::Running {
                if let Err(e) = plugin.handle_message(message).await {
                    error!("Plugin '{}' error handling message: {}", name, e);
                }
            }
        }
        
        // Run post-receive hooks
        self.run_hooks(HookPoint::PostReceive, message).await?;
        
        Ok(())
    }
    
    /// Filter outgoing message through all plugins
    pub async fn filter_outgoing(&self, message: &mut IrcMessage) -> Result<bool> {
        // Run pre-send hooks
        self.run_hooks(HookPoint::PreSend, message).await?;
        
        // Let each plugin filter the message
        let mut plugins = self.plugins.write().await;
        for (name, plugin) in plugins.iter_mut() {
            if plugin.state() == PluginState::Running {
                match plugin.filter_outgoing(message).await {
                    Ok(true) => continue,
                    Ok(false) => {
                        info!("Plugin '{}' blocked outgoing message", name);
                        return Ok(false);
                    }
                    Err(e) => {
                        error!("Plugin '{}' error filtering message: {}", name, e);
                    }
                }
            }
        }
        
        // Run post-send hooks
        self.run_hooks(HookPoint::PostSend, message).await?;
        
        Ok(true)
    }
    
    /// Run hooks for a specific hook point
    async fn run_hooks(&self, point: HookPoint, message: &IrcMessage) -> Result<()> {
        let hooks = self.hooks.read().await;
        if let Some(hook_list) = hooks.get(&point) {
            for (plugin_name, hook_fn) in hook_list {
                if let Err(e) = hook_fn(message) {
                    error!("Hook error in plugin '{}' at {:?}: {}", plugin_name, point, e);
                }
            }
        }
        Ok(())
    }
    
    /// Execute a plugin command
    pub async fn execute_command(&self, plugin_name: &str, command: &str, args: &[String]) -> Result<String> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins.get_mut(plugin_name)
            .ok_or_else(|| anyhow!("Plugin '{}' not loaded", plugin_name))?;
        
        plugin.handle_command(command, args).await
    }
    
    /// List loaded plugins
    pub async fn list_loaded(&self) -> Vec<(String, PluginState)> {
        let plugins = self.plugins.read().await;
        plugins.iter()
            .map(|(name, plugin)| (name.clone(), plugin.state()))
            .collect()
    }
    
    /// List available plugins
    pub fn list_available(&self) -> Vec<&str> {
        self.registry.list()
    }
    
    /// Get plugin info
    pub async fn get_plugin_info(&self, name: &str) -> Option<String> {
        let plugins = self.plugins.read().await;
        plugins.get(name).map(|plugin| {
            let info = plugin.info();
            format!("{} v{} by {} - {}", 
                info.name, info.version, info.author, info.description)
        })
    }
}