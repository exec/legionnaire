//! Legion Protocol administrative command handling
//! 
//! Provides IRC command handlers for Legion Protocol channel administration
//! and management features.

use crate::error::{IronError, Result};
use crate::legion::{LegionClient, LegionEvent};
use legion_protocol::{AdminOperation, MemberOperation, BanOperation, KeyOperation, 
                     MemberRole, ChannelMode, ChannelSettings, Permission};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Duration};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

/// Admin command handler for Legion Protocol channels
pub struct AdminCommandHandler {
    /// Legion client for operations
    legion_client: LegionClient,
    /// Command aliases and shortcuts
    command_aliases: HashMap<String, String>,
    /// User command history for rate limiting
    command_history: RwLock<HashMap<String, Vec<SystemTime>>>,
    /// Rate limiting settings
    rate_limit_config: RateLimitConfig,
}

/// Rate limiting configuration for admin commands
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Commands per minute
    pub commands_per_minute: u32,
    /// Burst allowance
    pub burst_allowance: u32,
    /// Cooldown period for failed commands
    pub failed_command_cooldown: Duration,
}

/// Parsed admin command
#[derive(Debug, Clone)]
pub struct AdminCommand {
    /// Command name
    pub command: String,
    /// Target channel
    pub channel: String,
    /// Command parameters
    pub params: Vec<String>,
    /// User issuing the command
    pub user: String,
}

/// Command execution result
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Whether the command succeeded
    pub success: bool,
    /// Result message to display
    pub message: String,
    /// Additional data (for complex responses)
    pub data: Option<CommandData>,
    /// Whether to broadcast the result to the channel
    pub broadcast: bool,
}

/// Additional data returned by commands
#[derive(Debug, Clone)]
pub enum CommandData {
    /// List of channel members
    MemberList(Vec<MemberInfo>),
    /// List of channel bans
    BanList(Vec<BanInfo>),
    /// Channel information
    ChannelInfo(ChannelInfo),
    /// Help information
    HelpInfo(Vec<HelpEntry>),
}

/// Member information for display
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub nickname: String,
    pub role: MemberRole,
    pub joined_at: SystemTime,
    pub is_online: bool,
}

/// Ban information for display
#[derive(Debug, Clone)]
pub struct BanInfo {
    pub pattern: String,
    pub reason: Option<String>,
    pub set_by: String,
    pub expires_at: Option<SystemTime>,
}

/// Channel information summary
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub name: String,
    pub topic: Option<String>,
    pub member_count: usize,
    pub modes: HashSet<ChannelMode>,
    pub created_at: SystemTime,
}

/// Help entry for command documentation
#[derive(Debug, Clone)]
pub struct HelpEntry {
    pub command: String,
    pub syntax: String,
    pub description: String,
    pub examples: Vec<String>,
    pub required_role: MemberRole,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            commands_per_minute: 30,
            burst_allowance: 5,
            failed_command_cooldown: Duration::from_secs(5),
        }
    }
}

impl AdminCommandHandler {
    /// Create a new admin command handler
    pub fn new(legion_client: LegionClient, rate_limit_config: RateLimitConfig) -> Self {
        let mut command_aliases = HashMap::new();
        
        // Set up common aliases
        command_aliases.insert("k".to_string(), "kick".to_string());
        command_aliases.insert("b".to_string(), "ban".to_string());
        command_aliases.insert("ub".to_string(), "unban".to_string());
        command_aliases.insert("o".to_string(), "op".to_string());
        command_aliases.insert("do".to_string(), "deop".to_string());
        command_aliases.insert("v".to_string(), "voice".to_string());
        command_aliases.insert("dv".to_string(), "devoice".to_string());
        command_aliases.insert("t".to_string(), "topic".to_string());
        command_aliases.insert("m".to_string(), "mode".to_string());
        command_aliases.insert("kr".to_string(), "keyrotate".to_string());
        command_aliases.insert("ml".to_string(), "memberlist".to_string());
        command_aliases.insert("bl".to_string(), "banlist".to_string());
        
        Self {
            legion_client,
            command_aliases,
            command_history: RwLock::new(HashMap::new()),
            rate_limit_config,
        }
    }
    
    /// Process an admin command from IRC input
    pub async fn process_command(&self, input: &str, user: &str, channel: &str) -> Result<CommandResult> {
        // Parse the command
        let command = self.parse_command(input, user, channel)?;
        
        // Check rate limiting
        if !self.check_rate_limit(&command.user).await? {
            return Ok(CommandResult {
                success: false,
                message: "Rate limit exceeded. Please slow down.".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        // Execute the command
        let result = self.execute_command(command).await;
        
        // Update rate limiting history
        let success = result.as_ref().map(|r| r.success).unwrap_or(false);
        self.update_rate_limit_history(&user, success).await?;
        
        result
    }
    
    /// Parse IRC input into an admin command
    fn parse_command(&self, input: &str, user: &str, channel: &str) -> Result<AdminCommand> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Err(IronError::Parse("Empty command".to_string()));
        }
        
        let mut command = parts[0].to_lowercase();
        
        // Handle command prefix (!, /, etc.)
        if command.starts_with('!') || command.starts_with('/') {
            command = command[1..].to_string();
        }
        
        // Resolve aliases
        if let Some(resolved) = self.command_aliases.get(&command) {
            command = resolved.clone();
        }
        
        let params = parts[1..].iter().map(|s| s.to_string()).collect();
        
        Ok(AdminCommand {
            command,
            channel: channel.to_string(),
            params,
            user: user.to_string(),
        })
    }
    
    /// Execute an admin command
    async fn execute_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        match cmd.command.as_str() {
            "kick" => self.handle_kick_command(cmd).await,
            "ban" => self.handle_ban_command(cmd).await,
            "unban" => self.handle_unban_command(cmd).await,
            "op" => self.handle_op_command(cmd).await,
            "deop" => self.handle_deop_command(cmd).await,
            "voice" => self.handle_voice_command(cmd).await,
            "devoice" => self.handle_devoice_command(cmd).await,
            "topic" => self.handle_topic_command(cmd).await,
            "mode" => self.handle_mode_command(cmd).await,
            "keyrotate" => self.handle_key_rotation_command(cmd).await,
            "memberlist" => self.handle_member_list_command(cmd).await,
            "banlist" => self.handle_ban_list_command(cmd).await,
            "channelinfo" => self.handle_channel_info_command(cmd).await,
            "setrole" => self.handle_set_role_command(cmd).await,
            "invite" => self.handle_invite_command(cmd).await,
            "mute" => self.handle_mute_command(cmd).await,
            "unmute" => self.handle_unmute_command(cmd).await,
            "help" => self.handle_help_command(cmd).await,
            _ => Ok(CommandResult {
                success: false,
                message: format!("Unknown command: {}. Type !help for available commands.", cmd.command),
                data: None,
                broadcast: false,
            }),
        }
    }
    
    /// Handle kick command
    async fn handle_kick_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !kick <user> [reason]".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        let reason = if cmd.params.len() > 1 {
            Some(cmd.params[1..].join(" "))
        } else {
            None
        };
        
        // TODO: Integrate with actual Legion client admin operations
        // For now, return a mock result
        Ok(CommandResult {
            success: true,
            message: format!("Kicked {} from {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle ban command
    async fn handle_ban_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !ban <user|pattern> [duration] [reason]".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let pattern = &cmd.params[0];
        let mut duration = None;
        let mut reason = None;
        
        // Parse optional duration and reason
        if cmd.params.len() > 1 {
            // Try to parse duration (e.g., "1h", "30m", "1d")
            if let Ok(parsed_duration) = self.parse_duration(&cmd.params[1]) {
                duration = Some(SystemTime::now() + parsed_duration);
                if cmd.params.len() > 2 {
                    reason = Some(cmd.params[2..].join(" "));
                }
            } else {
                // No duration, treat as reason
                reason = Some(cmd.params[1..].join(" "));
            }
        }
        
        let duration_str = if duration.is_some() {
            format!(" for {}", &cmd.params[1])
        } else {
            " permanently".to_string()
        };
        
        Ok(CommandResult {
            success: true,
            message: format!("Banned {}{} from {}", pattern, duration_str, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle unban command
    async fn handle_unban_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !unban <user|pattern>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let pattern = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Unbanned {} from {}", pattern, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle op command
    async fn handle_op_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !op <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Granted operator status to {} in {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle deop command
    async fn handle_deop_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !deop <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Removed operator status from {} in {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle voice command
    async fn handle_voice_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !voice <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Granted voice to {} in {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle devoice command
    async fn handle_devoice_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !devoice <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Removed voice from {} in {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle topic command
    async fn handle_topic_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            // Get current topic
            return Ok(CommandResult {
                success: true,
                message: format!("Current topic for {}: No topic set", cmd.channel),
                data: None,
                broadcast: false,
            });
        }
        
        let topic = cmd.params.join(" ");
        
        Ok(CommandResult {
            success: true,
            message: format!("Topic for {} set to: {}", cmd.channel, topic),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle mode command
    async fn handle_mode_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !mode <+|-><mode> [params]".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let mode_str = &cmd.params[0];
        let enable = mode_str.starts_with('+');
        let mode_char = mode_str.chars().nth(1).unwrap_or('?');
        
        let mode_name = match mode_char {
            'm' => "moderated",
            'i' => "invite-only",
            't' => "topic protection",
            's' => "secret",
            'p' => "private",
            'k' => "key rotation",
            _ => "unknown",
        };
        
        Ok(CommandResult {
            success: true,
            message: format!("Mode {} {} for {}", mode_name, 
                           if enable { "enabled" } else { "disabled" }, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle key rotation command
    async fn handle_key_rotation_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        // This would integrate with the actual Legion client key rotation
        Ok(CommandResult {
            success: true,
            message: format!("Key rotation initiated for {}", cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle member list command
    async fn handle_member_list_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        // Mock member list - in practice this would query the Legion client
        let members = vec![
            MemberInfo {
                nickname: "alice".to_string(),
                role: MemberRole::Owner,
                joined_at: SystemTime::now() - Duration::from_secs(3600),
                is_online: true,
            },
            MemberInfo {
                nickname: "bob".to_string(),
                role: MemberRole::Operator,
                joined_at: SystemTime::now() - Duration::from_secs(1800),
                is_online: true,
            },
            MemberInfo {
                nickname: "charlie".to_string(),
                role: MemberRole::Member,
                joined_at: SystemTime::now() - Duration::from_secs(900),
                is_online: false,
            },
        ];
        
        Ok(CommandResult {
            success: true,
            message: format!("Member list for {} ({} members)", cmd.channel, members.len()),
            data: Some(CommandData::MemberList(members)),
            broadcast: false,
        })
    }
    
    /// Handle ban list command
    async fn handle_ban_list_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        // Mock ban list - in practice this would query the Legion client
        let bans = vec![
            BanInfo {
                pattern: "*@spam.com".to_string(),
                reason: Some("Spam domain".to_string()),
                set_by: "admin".to_string(),
                expires_at: None,
            },
        ];
        
        Ok(CommandResult {
            success: true,
            message: format!("Ban list for {} ({} bans)", cmd.channel, bans.len()),
            data: Some(CommandData::BanList(bans)),
            broadcast: false,
        })
    }
    
    /// Handle channel info command
    async fn handle_channel_info_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        let info = ChannelInfo {
            name: cmd.channel.clone(),
            topic: Some("Welcome to the Legion encrypted channel".to_string()),
            member_count: 5,
            modes: {
                let mut modes = HashSet::new();
                modes.insert(ChannelMode::KeyRotation);
                modes.insert(ChannelMode::TopicProtected);
                modes
            },
            created_at: SystemTime::now() - Duration::from_secs(86400),
        };
        
        Ok(CommandResult {
            success: true,
            message: format!("Channel information for {}", cmd.channel),
            data: Some(CommandData::ChannelInfo(info)),
            broadcast: false,
        })
    }
    
    /// Handle set role command
    async fn handle_set_role_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.len() < 2 {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !setrole <user> <role>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        let role = &cmd.params[1];
        
        Ok(CommandResult {
            success: true,
            message: format!("Set role of {} to {} in {}", target, role, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle invite command
    async fn handle_invite_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !invite <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Invited {} to {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle mute command
    async fn handle_mute_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !mute <user> [duration]".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        let duration_str = cmd.params.get(1).cloned().unwrap_or_else(|| "indefinitely".to_string());
        
        Ok(CommandResult {
            success: true,
            message: format!("Muted {} in {} {}", target, cmd.channel, duration_str),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle unmute command
    async fn handle_unmute_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        if cmd.params.is_empty() {
            return Ok(CommandResult {
                success: false,
                message: "Usage: !unmute <user>".to_string(),
                data: None,
                broadcast: false,
            });
        }
        
        let target = &cmd.params[0];
        
        Ok(CommandResult {
            success: true,
            message: format!("Unmuted {} in {}", target, cmd.channel),
            data: None,
            broadcast: true,
        })
    }
    
    /// Handle help command
    async fn handle_help_command(&self, cmd: AdminCommand) -> Result<CommandResult> {
        let help_entries = vec![
            HelpEntry {
                command: "kick".to_string(),
                syntax: "!kick <user> [reason]".to_string(),
                description: "Remove a user from the channel".to_string(),
                examples: vec!["!kick spammer", "!kick trolluser Inappropriate behavior"].iter().map(|s| s.to_string()).collect(),
                required_role: MemberRole::Operator,
            },
            HelpEntry {
                command: "ban".to_string(),
                syntax: "!ban <user|pattern> [duration] [reason]".to_string(),
                description: "Ban a user or pattern from the channel".to_string(),
                examples: vec!["!ban spammer", "!ban *@spam.com 1d Spam domain", "!ban trolluser Permanent ban"].iter().map(|s| s.to_string()).collect(),
                required_role: MemberRole::Operator,
            },
            HelpEntry {
                command: "topic".to_string(),
                syntax: "!topic [new topic]".to_string(),
                description: "View or set the channel topic".to_string(),
                examples: vec!["!topic", "!topic Welcome to our secure channel!"].iter().map(|s| s.to_string()).collect(),
                required_role: MemberRole::HalfOp,
            },
            HelpEntry {
                command: "keyrotate".to_string(),
                syntax: "!keyrotate".to_string(),
                description: "Initiate encryption key rotation for the channel".to_string(),
                examples: vec!["!keyrotate"].iter().map(|s| s.to_string()).collect(),
                required_role: MemberRole::Admin,
            },
            HelpEntry {
                command: "memberlist".to_string(),
                syntax: "!memberlist".to_string(),
                description: "Show list of channel members and their roles".to_string(),
                examples: vec!["!memberlist"].iter().map(|s| s.to_string()).collect(),
                required_role: MemberRole::Member,
            },
        ];
        
        Ok(CommandResult {
            success: true,
            message: "Available admin commands:".to_string(),
            data: Some(CommandData::HelpInfo(help_entries)),
            broadcast: false,
        })
    }
    
    /// Parse duration string (e.g., "1h", "30m", "7d") into Duration
    fn parse_duration(&self, duration_str: &str) -> std::result::Result<Duration, &'static str> {
        if duration_str.is_empty() {
            return Err("Empty duration");
        }
        
        let (number_str, unit) = if let Some(last_char) = duration_str.chars().last() {
            if last_char.is_alphabetic() {
                (&duration_str[..duration_str.len()-1], last_char)
            } else {
                (duration_str, 's') // Default to seconds
            }
        } else {
            return Err("Invalid duration format");
        };
        
        let number: u64 = number_str.parse().map_err(|_| "Invalid number")?;
        
        let duration = match unit.to_lowercase().next().unwrap() {
            's' => Duration::from_secs(number),
            'm' => Duration::from_secs(number * 60),
            'h' => Duration::from_secs(number * 3600),
            'd' => Duration::from_secs(number * 86400),
            'w' => Duration::from_secs(number * 604800),
            _ => return Err("Invalid time unit"),
        };
        
        Ok(duration)
    }
    
    /// Check if user is within rate limits
    async fn check_rate_limit(&self, user: &str) -> Result<bool> {
        let mut history = self.command_history.write().await;
        let now = SystemTime::now();
        let window_start = now - Duration::from_secs(60);
        
        let user_history = history.entry(user.to_string()).or_insert_with(Vec::new);
        
        // Remove old entries
        user_history.retain(|&timestamp| timestamp > window_start);
        
        // Check if user has exceeded rate limit
        if user_history.len() >= self.rate_limit_config.commands_per_minute as usize {
            return Ok(false);
        }
        
        // Check burst allowance
        let recent_commands = user_history.iter()
            .filter(|&&timestamp| timestamp > now - Duration::from_secs(10))
            .count();
        
        if recent_commands >= self.rate_limit_config.burst_allowance as usize {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Update rate limit history after command execution
    async fn update_rate_limit_history(&self, user: &str, success: bool) -> Result<()> {
        let mut history = self.command_history.write().await;
        let user_history = history.entry(user.to_string()).or_insert_with(Vec::new);
        
        user_history.push(SystemTime::now());
        
        // If command failed, add extra cooldown entries
        if !success {
            for _ in 0..3 {
                user_history.push(SystemTime::now());
            }
        }
        
        Ok(())
    }
    
    /// Format command result for display
    pub fn format_result(&self, result: &CommandResult) -> Vec<String> {
        let mut lines = vec![result.message.clone()];
        
        if let Some(ref data) = result.data {
            match data {
                CommandData::MemberList(members) => {
                    lines.push("Members:".to_string());
                    for member in members {
                        let status = if member.is_online { "●" } else { "○" };
                        lines.push(format!("  {} {} ({:?})", status, member.nickname, member.role));
                    }
                },
                CommandData::BanList(bans) => {
                    lines.push("Banned patterns:".to_string());
                    for ban in bans {
                        let expires = if let Some(expires_at) = ban.expires_at {
                            format!(" (expires in {:?})", expires_at.duration_since(SystemTime::now()).unwrap_or_default())
                        } else {
                            " (permanent)".to_string()
                        };
                        lines.push(format!("  {} - {} by {}{}", 
                                          ban.pattern, 
                                          ban.reason.as_deref().unwrap_or("No reason"),
                                          ban.set_by,
                                          expires));
                    }
                },
                CommandData::ChannelInfo(info) => {
                    lines.push(format!("Channel: {}", info.name));
                    lines.push(format!("Topic: {}", info.topic.as_deref().unwrap_or("No topic")));
                    lines.push(format!("Members: {}", info.member_count));
                    lines.push(format!("Modes: {:?}", info.modes));
                },
                CommandData::HelpInfo(help) => {
                    lines.push("Command syntax and usage:".to_string());
                    for entry in help {
                        lines.push(format!("  {} - {} (requires: {:?})", 
                                          entry.syntax, entry.description, entry.required_role));
                        for example in &entry.examples {
                            lines.push(format!("    Example: {}", example));
                        }
                    }
                },
            }
        }
        
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legion::LegionConfig;
    
    #[tokio::test]
    async fn test_command_parsing() {
        let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
        let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
        
        let cmd = handler.parse_command("!kick alice Spamming", "bob", "!test").unwrap();
        assert_eq!(cmd.command, "kick");
        assert_eq!(cmd.params, vec!["alice", "Spamming"]);
        assert_eq!(cmd.user, "bob");
        assert_eq!(cmd.channel, "!test");
    }
    
    #[tokio::test]
    async fn test_duration_parsing() {
        let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
        let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
        
        assert_eq!(handler.parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(handler.parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(handler.parse_duration("7d").unwrap(), Duration::from_secs(604800));
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
        let handler = AdminCommandHandler::new(legion_client, RateLimitConfig {
            commands_per_minute: 2,
            burst_allowance: 1,
            failed_command_cooldown: Duration::from_secs(1),
        });
        
        // First command should pass
        assert!(handler.check_rate_limit("user").await.unwrap());
        handler.update_rate_limit_history("user", true).await.unwrap();
        
        // Second command should pass
        assert!(handler.check_rate_limit("user").await.unwrap());
        handler.update_rate_limit_history("user", true).await.unwrap();
        
        // Third command should be rate limited
        assert!(!handler.check_rate_limit("user").await.unwrap());
    }
}