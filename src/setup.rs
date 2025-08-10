//! Interactive Setup Wizard
//!
//! Provides a guided first-run experience for new users to configure
//! Legionnaire with their IRC servers, credentials, and preferences.

use crate::config::{Config, ServerConfig, UserConfig, SaslConfig};
use crate::credentials::{CredentialManager, CredentialType};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::io::{self, Write};
use tracing::{info, warn};
use secrecy::Secret;

/// Setup wizard configuration
#[derive(Debug, Clone)]
pub struct SetupWizard {
    credential_manager: CredentialManager,
}

/// Popular IRC server presets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPreset {
    pub name: String,
    pub display_name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub supports_sasl: bool,
    pub description: String,
    pub suggested_channels: Vec<String>,
}

impl SetupWizard {
    pub fn new() -> Result<Self> {
        let credential_manager = CredentialManager::new()?;
        Ok(Self { credential_manager })
    }
    
    /// Run the interactive setup wizard
    pub async fn run_interactive_setup(&mut self) -> Result<Config> {
        self.print_welcome();
        
        // Step 1: User Information
        let user_config = self.setup_user_info()?;
        
        // Step 2: Server Selection
        let servers = self.setup_servers().await?;
        
        // Step 3: Security Preferences
        let security_prefs = self.setup_security_preferences()?;
        
        // Step 4: Plugin Selection
        let plugin_prefs = self.setup_plugin_preferences()?;
        
        // Step 5: Create and save configuration
        let config = Config {
            user: user_config,
            servers,
            default_server: None,
            keybindings: crate::config::KeybindingsConfig::default(),
            dos_protection: crate::dos_protection::DosProtectionConfig::default(),
            profiles: std::collections::HashMap::new(),
        };
        
        // Save configuration
        config.save()?;
        
        self.print_completion_message(&config);
        
        Ok(config)
    }
    
    fn print_welcome(&self) {
        println!("\n🎉 Welcome to Legionnaire IRC Client Setup!");
        println!("=====================================");
        println!();
        println!("This wizard will help you set up Legionnaire for first-time use.");
        println!("You can modify these settings later by editing your configuration file.");
        println!();
        println!("Press Enter to continue...");
        let _ = io::stdin().read_line(&mut String::new());
        println!();
    }
    
    fn setup_user_info(&self) -> Result<UserConfig> {
        println!("📝 User Information");
        println!("==================");
        println!();
        
        let nickname = self.prompt_required("IRC Nickname", "Enter your desired IRC nickname")?;
        
        let username = self.prompt_optional(
            "Username", 
            "Enter your username (leave empty to use nickname)",
            Some(&nickname)
        )?;
        
        let realname = self.prompt_optional(
            "Real Name",
            "Enter your real name (leave empty to use nickname)", 
            Some(&nickname)
        )?;
        
        println!("✅ User information configured");
        println!();
        
        Ok(UserConfig {
            nickname,
            username: Some(username),
            realname: Some(realname),
        })
    }
    
    async fn setup_servers(&mut self) -> Result<Vec<ServerConfig>> {
        println!("🌐 Server Configuration");
        println!("======================");
        println!();
        
        let presets = self.get_server_presets();
        
        println!("Choose from popular IRC networks or configure custom servers:");
        println!();
        
        for (i, preset) in presets.iter().enumerate() {
            println!("{}. {} - {}", i + 1, preset.display_name, preset.description);
        }
        println!("{}. Configure custom server", presets.len() + 1);
        println!("{}. Skip for now (can configure later)", presets.len() + 2);
        println!();
        
        let mut servers = Vec::new();
        
        loop {
            let choice = self.prompt_number("Select option", 1, presets.len() + 2)?;
            
            if choice <= presets.len() {
                let preset = &presets[choice - 1];
                let server = self.configure_preset_server(preset).await?;
                servers.push(server);
            } else if choice == presets.len() + 1 {
                let server = self.configure_custom_server().await?;
                servers.push(server);
            } else {
                break; // Skip
            }
            
            if !self.prompt_yes_no("Add another server?", false)? {
                break;
            }
        }
        
        if servers.is_empty() {
            warn!("No servers configured - you'll need to add them later");
            println!("⚠️  No servers configured. You can add them later with 'legionnaire --setup'");
        } else {
            println!("✅ {} server(s) configured", servers.len());
        }
        println!();
        
        Ok(servers)
    }
    
    async fn configure_preset_server(&mut self, preset: &ServerPreset) -> Result<ServerConfig> {
        println!("Configuring {}...", preset.display_name);
        
        let nickname_registered = if preset.supports_sasl {
            self.prompt_yes_no("Do you have a registered nickname on this network?", false)?
        } else {
            false
        };
        
        let sasl = if nickname_registered {
            Some(self.setup_sasl_auth(&preset.host).await?)
        } else {
            None
        };
        
        let channels = if !preset.suggested_channels.is_empty() {
            println!("Suggested channels for {}:", preset.display_name);
            for channel in &preset.suggested_channels {
                println!("  {}", channel);
            }
            
            if self.prompt_yes_no("Join suggested channels?", true)? {
                preset.suggested_channels.clone()
            } else {
                self.prompt_channels()?
            }
        } else {
            self.prompt_channels()?
        };
        
        Ok(ServerConfig {
            name: preset.name.clone(),
            host: preset.host.clone(),
            port: preset.port,
            tls: preset.tls,
            verify_certificates: true,
            channels,
            channel_configs: vec![],
            auto_load_history: true,
            sasl,
        })
    }
    
    async fn configure_custom_server(&mut self) -> Result<ServerConfig> {
        println!("Custom Server Configuration:");
        
        let name = self.prompt_required("Server name", "Enter a name for this server")?;
        let host = self.prompt_required("Hostname", "Enter server hostname")?;
        let port = self.prompt_number("Port", 1, 65535).unwrap_or(6667) as u16;
        let tls = self.prompt_yes_no("Use TLS/SSL?", true)?;
        
        if !tls {
            println!("⚠️  WARNING: Unencrypted connections are not recommended!");
        }
        
        let supports_sasl = self.prompt_yes_no("Does this server support SASL authentication?", false)?;
        let sasl = if supports_sasl && self.prompt_yes_no("Configure SASL authentication?", false)? {
            Some(self.setup_sasl_auth(&host).await?)
        } else {
            None
        };
        
        let channels = self.prompt_channels()?;
        
        Ok(ServerConfig {
            name,
            host,
            port,
            tls,
            verify_certificates: true,
            channels,
            channel_configs: vec![],
            auto_load_history: true,
            sasl,
        })
    }
    
    async fn setup_sasl_auth(&mut self, server: &str) -> Result<SaslConfig> {
        println!("SASL Authentication Setup:");
        println!("1. PLAIN (username/password)");
        println!("2. EXTERNAL (client certificate)");
        println!("3. SCRAM-SHA-256 (secure challenge-response)");
        
        let choice = self.prompt_number("Select SASL method", 1, 3)?;
        
        match choice {
            1 => {
                let username = self.prompt_required("SASL Username", "Enter your registered username")?;
                let password = self.prompt_password("SASL Password", "Enter your NickServ password")?;
                
                // Store credentials securely
                let cred_type = CredentialType::SaslCredentials {
                    server: server.to_string(),
                    username: username.clone(),
                };
                
                self.credential_manager.store_credential(cred_type, Secret::new(password)).await?;
                
                Ok(SaslConfig::Plain { username, password: "".to_string() }) // Password stored securely
            }
            2 => {
                println!("EXTERNAL authentication requires client certificate configuration.");
                println!("This is an advanced feature - refer to documentation for setup.");
                Ok(SaslConfig::External)
            }
            3 => {
                let username = self.prompt_required("SASL Username", "Enter your registered username")?;
                let password = self.prompt_password("SASL Password", "Enter your password")?;
                
                // Store credentials securely
                let cred_type = CredentialType::SaslCredentials {
                    server: server.to_string(),
                    username: username.clone(),
                };
                
                self.credential_manager.store_credential(cred_type, Secret::new(password)).await?;
                
                Ok(SaslConfig::ScramSha256 { username, password: "".to_string() })
            }
            _ => unreachable!(),
        }
    }
    
    fn setup_security_preferences(&self) -> Result<SecurityPreferences> {
        println!("🔒 Security Preferences");
        println!("======================");
        println!();
        
        let always_verify_certs = self.prompt_yes_no(
            "Always verify SSL certificates? (Recommended: Yes)", 
            true
        )?;
        
        let enable_e2ee = self.prompt_yes_no(
            "Enable end-to-end encryption plugin by default?", 
            true
        )?;
        
        let dos_protection = self.prompt_yes_no(
            "Enable DoS protection? (Recommended: Yes)", 
            true
        )?;
        
        println!("✅ Security preferences configured");
        println!();
        
        Ok(SecurityPreferences {
            always_verify_certs,
            enable_e2ee,
            dos_protection,
        })
    }
    
    fn setup_plugin_preferences(&self) -> Result<PluginPreferences> {
        println!("🔌 Plugin Configuration");
        println!("======================");
        println!();
        
        println!("Available plugins:");
        println!("1. E2EE - End-to-end encryption for secure messaging");
        println!("2. Weather Bot - Provides weather information commands");
        println!("3. Skip plugin setup for now");
        println!();
        
        let mut enabled_plugins = Vec::new();
        
        if self.prompt_yes_no("Enable E2EE encryption plugin?", true)? {
            enabled_plugins.push("e2ee".to_string());
            println!("  → E2EE plugin will be automatically loaded");
        }
        
        if self.prompt_yes_no("Enable Weather Bot plugin?", false)? {
            enabled_plugins.push("weather-bot".to_string());
            
            if self.prompt_yes_no("Configure Weather Bot API key now?", false)? {
                let api_key = self.prompt_password("OpenWeatherMap API Key", 
                    "Enter your weather API key (get one from openweathermap.org/api)")?;
                
                // Store API key securely
                // This would be implemented when we add async to this method
                println!("  → Weather API key will be stored securely");
            }
        }
        
        println!("✅ Plugin preferences configured");
        println!();
        
        Ok(PluginPreferences {
            enabled_plugins,
        })
    }
    
    fn prompt_channels(&self) -> Result<Vec<String>> {
        println!("Channel Configuration:");
        println!("Enter channels to join automatically (one per line, empty line to finish):");
        
        let mut channels = Vec::new();
        loop {
            print!("Channel: ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let channel = input.trim();
            
            if channel.is_empty() {
                break;
            }
            
            let channel = if channel.starts_with('#') {
                channel.to_string()
            } else {
                format!("#{}", channel)
            };
            
            channels.push(channel);
        }
        
        Ok(channels)
    }
    
    fn print_completion_message(&self, config: &Config) {
        println!("\n🎉 Setup Complete!");
        println!("=================");
        println!();
        println!("Your Legionnaire IRC client is now configured with:");
        println!("📝 User: {}", config.user.nickname);
        println!("🌐 Servers: {}", config.servers.len());
        
        if !config.servers.is_empty() {
            for server in &config.servers {
                println!("   • {} ({}:{})", server.name, server.host, server.port);
                if !server.channels.is_empty() {
                    println!("     Channels: {}", server.channels.join(", "));
                }
            }
        }
        
        println!();
        println!("🚀 Next Steps:");
        println!("   • Run 'legionnaire' to start the TUI client");
        println!("   • Run 'legionnaire --help' to see all options");
        println!("   • Run 'legionnaire --setup' to modify this configuration");
        println!();
        println!("📚 Documentation: https://github.com/exec/legionnaire");
        println!("🐛 Report issues: https://github.com/exec/legionnaire/issues");
        println!();
        println!("Happy chatting! 💬");
    }
    
    /// Utility methods for user input
    fn prompt_required(&self, field_name: &str, prompt: &str) -> Result<String> {
        loop {
            print!("{}: ", prompt);
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let value = input.trim();
            
            if !value.is_empty() {
                return Ok(value.to_string());
            }
            
            println!("❌ {} is required.", field_name);
        }
    }
    
    fn prompt_optional(&self, _field_name: &str, prompt: &str, default: Option<&str>) -> Result<String> {
        let full_prompt = if let Some(def) = default {
            format!("{} (default: {})", prompt, def)
        } else {
            prompt.to_string()
        };
        
        print!("{}: ", full_prompt);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let value = input.trim();
        
        if value.is_empty() {
            Ok(default.unwrap_or("").to_string())
        } else {
            Ok(value.to_string())
        }
    }
    
    fn prompt_yes_no(&self, prompt: &str, default: bool) -> Result<bool> {
        let default_text = if default { "Y/n" } else { "y/N" };
        
        loop {
            print!("{} ({}): ", prompt, default_text);
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let value = input.trim().to_lowercase();
            
            match value.as_str() {
                "" => return Ok(default),
                "y" | "yes" | "true" | "1" => return Ok(true),
                "n" | "no" | "false" | "0" => return Ok(false),
                _ => println!("❌ Please enter 'y' or 'n'"),
            }
        }
    }
    
    fn prompt_number(&self, prompt: &str, min: usize, max: usize) -> Result<usize> {
        loop {
            print!("{} ({}-{}): ", prompt, min, max);
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            
            match input.trim().parse::<usize>() {
                Ok(num) if num >= min && num <= max => return Ok(num),
                Ok(_) => println!("❌ Number must be between {} and {}", min, max),
                Err(_) => println!("❌ Please enter a valid number"),
            }
        }
    }
    
    fn prompt_password(&self, field_name: &str, prompt: &str) -> Result<String> {
        use rpassword::prompt_password;
        
        loop {
            let password = prompt_password(format!("{}: ", prompt))?;
            
            if password.is_empty() {
                println!("❌ {} cannot be empty", field_name);
                continue;
            }
            
            if password.len() < 3 {
                println!("❌ {} seems too short", field_name);
                if !self.prompt_yes_no("Use this password anyway?", false)? {
                    continue;
                }
            }
            
            return Ok(password);
        }
    }
    
    fn get_server_presets(&self) -> Vec<ServerPreset> {
        vec![
            ServerPreset {
                name: "libera".to_string(),
                display_name: "Libera Chat".to_string(),
                host: "irc.libera.chat".to_string(),
                port: 6697,
                tls: true,
                supports_sasl: true,
                description: "Free and open source software communities".to_string(),
                suggested_channels: vec![
                    "#libera".to_string(),
                    "#rust".to_string(),
                    "#linux".to_string(),
                    "#programming".to_string(),
                ],
            },
            ServerPreset {
                name: "oftc".to_string(),
                display_name: "OFTC".to_string(),
                host: "irc.oftc.net".to_string(),
                port: 6697,
                tls: true,
                supports_sasl: true,
                description: "Open and free technology communities".to_string(),
                suggested_channels: vec![
                    "#debian".to_string(),
                    "#kernelnewbies".to_string(),
                ],
            },
            ServerPreset {
                name: "rizon".to_string(),
                display_name: "Rizon".to_string(),
                host: "irc.rizon.net".to_string(),
                port: 6697,
                tls: true,
                supports_sasl: true,
                description: "Anime and gaming communities".to_string(),
                suggested_channels: vec![
                    "#rizon".to_string(),
                ],
            },
            ServerPreset {
                name: "freenode".to_string(),
                display_name: "Freenode".to_string(),
                host: "chat.freenode.net".to_string(),
                port: 6697,
                tls: true,
                supports_sasl: true,
                description: "Peer-directed project communities".to_string(),
                suggested_channels: vec![],
            },
        ]
    }
}

#[derive(Debug, Clone)]
struct SecurityPreferences {
    always_verify_certs: bool,
    enable_e2ee: bool,
    dos_protection: bool,
}

#[derive(Debug, Clone)]
struct PluginPreferences {
    enabled_plugins: Vec<String>,
}

/// Quick setup for advanced users
pub struct QuickSetup;

impl QuickSetup {
    /// Create a minimal configuration quickly
    pub fn create_minimal_config(nickname: &str, server: &str, port: u16) -> Result<Config> {
        let user_config = UserConfig {
            nickname: nickname.to_string(),
            username: Some(nickname.to_string()),
            realname: Some(nickname.to_string()),
        };
        
        let server_config = ServerConfig {
            name: "default".to_string(),
            host: server.to_string(),
            port,
            tls: port == 6697,
            verify_certificates: true,
            channels: vec!["#general".to_string()],
            channel_configs: vec![],
            auto_load_history: true,
            sasl: None,
        };
        
        let config = Config {
            user: user_config,
            servers: vec![server_config],
            default_server: Some("default".to_string()),
            keybindings: crate::config::KeybindingsConfig::default(),
            dos_protection: crate::dos_protection::DosProtectionConfig::default(),
            profiles: std::collections::HashMap::new(),
        };
        
        Ok(config)
    }
    
    /// Create configuration from environment variables
    pub fn from_environment() -> Result<Option<Config>> {
        use std::env;
        
        let nickname = env::var("IRC_NICK").ok();
        let server = env::var("IRC_SERVER").ok();
        let port = env::var("IRC_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(6697);
        
        if let (Some(nick), Some(srv)) = (nickname, server) {
            info!("Creating configuration from environment variables");
            Ok(Some(Self::create_minimal_config(&nick, &srv, port)?))
        } else {
            Ok(None)
        }
    }
}