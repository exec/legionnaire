use crate::error::{IronError, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info};
use crossterm::event::{KeyCode, KeyModifiers};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    
    #[serde(default)]
    pub default_server: Option<String>,
    
    #[serde(default)]
    pub user: UserConfig,
    
    #[serde(default)]
    pub keybindings: KeybindingsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_tls")]
    pub tls: bool,
    #[serde(default = "default_verify_certs")]
    pub verify_certificates: bool,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub sasl: Option<SaslConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub nickname: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub realname: Option<String>,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            nickname: "ironchat_user".to_string(),
            username: None,
            realname: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mechanism")]
pub enum SaslConfig {
    Plain { username: String, password: String },
    External,
    #[serde(rename = "scram-sha-256")]
    ScramSha256 { username: String, password: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeybindingsConfig {
    #[serde(default = "default_help_key")]
    pub toggle_help: String,
    
    #[serde(default = "default_users_key")]
    pub toggle_users: String,
    
    #[serde(default = "default_quit_key")]
    pub quit: String,
    
    #[serde(default = "default_next_tab_key")]
    pub next_tab: String,
    
    #[serde(default = "default_prev_tab_key")]
    pub prev_tab: String,
    
    #[serde(default = "default_focus_next_key")]
    pub focus_next: String,
    
    #[serde(default = "default_focus_prev_key")]
    pub focus_prev: String,
    
    #[serde(default = "default_scroll_up_key")]
    pub scroll_up: String,
    
    #[serde(default = "default_scroll_down_key")]
    pub scroll_down: String,
    
    #[serde(default = "default_alt_next_tab_key")]
    pub alt_next_tab: String,
    
    #[serde(default = "default_alt_prev_tab_key")]
    pub alt_prev_tab: String,
}

fn default_port() -> u16 {
    6697
}

fn default_tls() -> bool {
    true
}

fn default_verify_certs() -> bool {
    true
}

fn default_help_key() -> String {
    "Ctrl+h".to_string()
}

fn default_users_key() -> String {
    "Ctrl+u".to_string()
}

fn default_quit_key() -> String {
    "Ctrl+c".to_string()
}

fn default_next_tab_key() -> String {
    "Ctrl+Down".to_string()
}

fn default_prev_tab_key() -> String {
    "Ctrl+Up".to_string()
}

fn default_focus_next_key() -> String {
    "Ctrl+Right".to_string()
}

fn default_focus_prev_key() -> String {
    "Ctrl+Left".to_string()
}

fn default_scroll_up_key() -> String {
    "Up".to_string()
}

fn default_scroll_down_key() -> String {
    "Down".to_string()
}

fn default_alt_next_tab_key() -> String {
    "F2".to_string()
}

fn default_alt_prev_tab_key() -> String {
    "F1".to_string()
}

impl Default for KeybindingsConfig {
    fn default() -> Self {
        Self {
            toggle_help: default_help_key(),
            toggle_users: default_users_key(),
            quit: default_quit_key(),
            next_tab: default_next_tab_key(),
            prev_tab: default_prev_tab_key(),
            focus_next: default_focus_next_key(),
            focus_prev: default_focus_prev_key(),
            scroll_up: default_scroll_up_key(),
            scroll_down: default_scroll_down_key(),
            alt_next_tab: default_alt_next_tab_key(),
            alt_prev_tab: default_alt_prev_tab_key(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            servers: vec![
                ServerConfig {
                    name: "Libera Chat".to_string(),
                    host: "irc.libera.chat".to_string(),
                    port: 6697,
                    tls: true,
                    verify_certificates: true,
                    channels: vec![],
                    sasl: None,
                },
                ServerConfig {
                    name: "OFTC".to_string(),
                    host: "irc.oftc.net".to_string(),
                    port: 6697,
                    tls: true,
                    verify_certificates: true,
                    channels: vec![],
                    sasl: None,
                },
            ],
            default_server: Some("Libera Chat".to_string()),
            user: UserConfig::default(),
            keybindings: KeybindingsConfig::default(),
        }
    }
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        if let Some(proj_dirs) = ProjectDirs::from("", "", "ironchat") {
            Ok(proj_dirs.config_dir().to_path_buf())
        } else {
            Err(IronError::Configuration("Could not determine config directory".to_string()))
        }
    }

    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        
        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)
                .map_err(|e| IronError::Configuration(format!("Failed to read config: {}", e)))?;
            
            toml::from_str(&contents)
                .map_err(|e| IronError::Configuration(format!("Failed to parse config: {}", e)))
        } else {
            debug!("Config file not found at {:?}, using defaults", config_path);
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_dir = Self::config_dir()?;
        let config_path = Self::config_path()?;
        
        // Create config directory if it doesn't exist
        fs::create_dir_all(&config_dir)
            .map_err(|e| IronError::Configuration(format!("Failed to create config directory: {}", e)))?;
        
        let contents = toml::to_string_pretty(self)
            .map_err(|e| IronError::Configuration(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(&config_path, contents)
            .map_err(|e| IronError::Configuration(format!("Failed to write config: {}", e)))?;
        
        info!("Configuration saved to: {}", config_path.display());
        Ok(())
    }

    pub async fn interactive_setup() -> Result<Self> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut stdout = io::stdout();
        
        stdout.write_all(b"\n=== IronChat Configuration Setup ===\n\n").await?;
        
        // Check if config exists
        let config_path = Self::config_path()?;
        if config_path.exists() {
            stdout.write_all(format!("Configuration file found at: {}\n", config_path.display()).as_bytes()).await?;
            stdout.write_all(b"Use existing configuration? [Y/n]: ").await?;
            stdout.flush().await?;
            
            let mut response = String::new();
            reader.read_line(&mut response).await?;
            
            if !response.trim().eq_ignore_ascii_case("n") {
                return Self::load();
            }
        }
        
        stdout.write_all(format!("\nConfiguration will be saved to: {}\n\n", config_path.display()).as_bytes()).await?;
        
        // Server selection
        stdout.write_all(b"Select IRC server:\n").await?;
        stdout.write_all(b"1) Libera Chat (irc.libera.chat)\n").await?;
        stdout.write_all(b"2) OFTC (irc.oftc.net)\n").await?;
        stdout.write_all(b"3) Custom server\n").await?;
        stdout.write_all(b"Choice [1]: ").await?;
        stdout.flush().await?;
        
        let mut choice = String::new();
        reader.read_line(&mut choice).await?;
        let choice = choice.trim();
        
        let mut server = match choice {
            "2" => ServerConfig {
                name: "OFTC".to_string(),
                host: "irc.oftc.net".to_string(),
                port: 6697,
                tls: true,
                verify_certificates: true,
                channels: vec![],
                sasl: None,
            },
            "3" => {
                stdout.write_all(b"\nServer hostname: ").await?;
                stdout.flush().await?;
                let mut host = String::new();
                reader.read_line(&mut host).await?;
                let host = host.trim().to_string();
                
                stdout.write_all(b"Server port [6697]: ").await?;
                stdout.flush().await?;
                let mut port_str = String::new();
                reader.read_line(&mut port_str).await?;
                let port = port_str.trim().parse().unwrap_or(6697);
                
                stdout.write_all(b"Use TLS encryption? [Y/n]: ").await?;
                stdout.flush().await?;
                let mut tls_str = String::new();
                reader.read_line(&mut tls_str).await?;
                let tls = !tls_str.trim().eq_ignore_ascii_case("n");
                
                ServerConfig {
                    name: host.clone(),
                    host,
                    port,
                    tls,
                    verify_certificates: true,
                    channels: vec![],
                    sasl: None,
                }
            }
            _ => ServerConfig {
                name: "Libera Chat".to_string(),
                host: "irc.libera.chat".to_string(),
                port: 6697,
                tls: true,
                verify_certificates: true,
                channels: vec![],
                sasl: None,
            },
        };
        
        // User info
        stdout.write_all(b"\nNickname: ").await?;
        stdout.flush().await?;
        let mut nickname = String::new();
        reader.read_line(&mut nickname).await?;
        let nickname = nickname.trim().to_string();
        
        stdout.write_all(b"Username [same as nickname]: ").await?;
        stdout.flush().await?;
        let mut username = String::new();
        reader.read_line(&mut username).await?;
        let username = username.trim();
        let username = if username.is_empty() { None } else { Some(username.to_string()) };
        
        stdout.write_all(b"Real name [same as nickname]: ").await?;
        stdout.flush().await?;
        let mut realname = String::new();
        reader.read_line(&mut realname).await?;
        let realname = realname.trim();
        let realname = if realname.is_empty() { None } else { Some(realname.to_string()) };
        
        // SASL
        stdout.write_all(b"\nConfigure SASL authentication? [y/N]: ").await?;
        stdout.flush().await?;
        let mut sasl_choice = String::new();
        reader.read_line(&mut sasl_choice).await?;
        
        if sasl_choice.trim().eq_ignore_ascii_case("y") {
            stdout.write_all(b"SASL mechanism:\n").await?;
            stdout.write_all(b"1) PLAIN\n").await?;
            stdout.write_all(b"2) EXTERNAL\n").await?;
            stdout.write_all(b"3) SCRAM-SHA-256\n").await?;
            stdout.write_all(b"Choice [1]: ").await?;
            stdout.flush().await?;
            
            let mut mech_choice = String::new();
            reader.read_line(&mut mech_choice).await?;
            
            server.sasl = match mech_choice.trim() {
                "2" => Some(SaslConfig::External),
                "3" => {
                    stdout.write_all(b"SASL username: ").await?;
                    stdout.flush().await?;
                    let mut sasl_user = String::new();
                    reader.read_line(&mut sasl_user).await?;
                    
                    stdout.write_all(b"SASL password: ").await?;
                    stdout.flush().await?;
                    let mut sasl_pass = String::new();
                    reader.read_line(&mut sasl_pass).await?;
                    
                    Some(SaslConfig::ScramSha256 {
                        username: sasl_user.trim().to_string(),
                        password: sasl_pass.trim().to_string(),
                    })
                }
                _ => {
                    stdout.write_all(b"SASL username: ").await?;
                    stdout.flush().await?;
                    let mut sasl_user = String::new();
                    reader.read_line(&mut sasl_user).await?;
                    
                    stdout.write_all(b"SASL password: ").await?;
                    stdout.flush().await?;
                    let mut sasl_pass = String::new();
                    reader.read_line(&mut sasl_pass).await?;
                    
                    Some(SaslConfig::Plain {
                        username: sasl_user.trim().to_string(),
                        password: sasl_pass.trim().to_string(),
                    })
                }
            };
        }
        
        // Channels
        stdout.write_all(b"\nChannels to join (comma-separated, e.g. #rust,#linux): ").await?;
        stdout.flush().await?;
        let mut channels = String::new();
        reader.read_line(&mut channels).await?;
        
        server.channels = channels
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| if s.starts_with('#') { s.to_string() } else { format!("#{}", s) })
            .collect();
        
        let config = Config {
            servers: vec![server.clone()],
            default_server: Some(server.name),
            user: UserConfig {
                nickname,
                username,
                realname,
            },
            keybindings: KeybindingsConfig::default(),
        };
        
        // Save config
        config.save()?;
        
        stdout.write_all(b"\nConfiguration saved successfully!\n").await?;
        stdout.write_all(b"You can edit the config file directly or run with --config flag.\n\n").await?;
        stdout.flush().await?;
        
        Ok(config)
    }

    pub fn get_server(&self, name: Option<&str>) -> Option<&ServerConfig> {
        if let Some(name) = name {
            self.servers.iter().find(|s| s.name == name)
        } else if let Some(ref default) = self.default_server {
            self.servers.iter().find(|s| &s.name == default)
        } else {
            self.servers.first()
        }
    }
}

impl KeybindingsConfig {
    pub fn parse_key(&self, key_str: &str) -> Option<(KeyCode, KeyModifiers)> {
        let mut modifiers = KeyModifiers::empty();
        let parts: Vec<&str> = key_str.split('+').collect();
        
        if parts.is_empty() {
            return None;
        }
        
        let key_part = parts.last()?;
        
        // Parse modifiers
        for part in &parts[..parts.len() - 1] {
            match part.to_lowercase().as_str() {
                "ctrl" => modifiers |= KeyModifiers::CONTROL,
                "alt" => modifiers |= KeyModifiers::ALT,
                "shift" => modifiers |= KeyModifiers::SHIFT,
                _ => continue,
            }
        }
        
        // Parse key
        let key_code = match key_part.to_lowercase().as_str() {
            "tab" => KeyCode::Tab,
            "enter" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "space" => KeyCode::Char(' '),
            "backspace" => KeyCode::Backspace,
            "delete" => KeyCode::Delete,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "pageup" => KeyCode::PageUp,
            "pagedown" => KeyCode::PageDown,
            s if s.len() == 1 => KeyCode::Char(s.chars().next()?),
            s if s.starts_with('f') && s.len() > 1 => {
                if let Ok(num) = s[1..].parse::<u8>() {
                    KeyCode::F(num)
                } else {
                    return None;
                }
            }
            _ => return None,
        };
        
        Some((key_code, modifiers))
    }
    
    pub fn matches_key(&self, binding: &str, code: KeyCode, modifiers: KeyModifiers) -> bool {
        if let Some((expected_code, expected_modifiers)) = self.parse_key(binding) {
            code == expected_code && modifiers == expected_modifiers
        } else {
            false
        }
    }
}