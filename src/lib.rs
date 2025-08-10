pub mod client;
pub mod connection;
pub mod connection_manager;
pub mod reliable_client;
// pub mod message; // Now using legion-protocol
// pub mod capabilities; // Now using legion-protocol
pub mod auth;
pub mod error;
pub mod logger;
pub mod ui;
// pub mod tui_simple; // Original with borrow checker issues
pub mod tui; // New working TUI
pub mod config;
pub mod dos_protection;
pub mod legion;
pub mod admin_commands;
pub mod plugin;
pub mod cli;
pub mod bouncer;
pub mod bot;
pub mod recovery;
pub mod credentials;
pub mod setup;
pub mod security;
pub mod monitoring;

pub use client::{IronClient, IrcConfig};
pub use reliable_client::ReliableIronClient;
pub use error::{IronError, ConnectionState, DisconnectReason};
pub use ui::IrcUi;
pub use tui::IrcTui; // Use new working TUI
pub use config::Config;
pub use dos_protection::DosProtection;
pub use legion::{LegionClient, LegionConfig, LegionEvent};
pub use admin_commands::{AdminCommandHandler, AdminCommand, CommandResult};
pub use bouncer::{Bouncer, BouncerConfig, BouncerStatus};
pub use bot::{BotFramework, BotConfig, Bot, BotInfo, BotCommand, BotContext, BotResponse};
pub use recovery::{RecoveryManager, RecoveryConfig, RecoveryState, RecoveryStats, ErrorHandler};
pub use credentials::{CredentialManager, CredentialType, CredentialBackend};
pub use setup::{SetupWizard, QuickSetup};
pub use security::{SecurityValidator, SecurityConfig, SecurityEvent, SecurityEventType, SecurityAction};
pub use monitoring::{PerformanceMonitor, MonitoringConfig, MetricsSnapshot, Alert};

// Re-export legion-protocol types for convenience
pub use legion_protocol::{
    IrcMessage, Command, Capability, CapabilitySet, CapabilityHandler,
    MessageReaction, ReactionAction, MessageReply,
    constants, utils
};
pub use legion_protocol::sasl::{SaslAuth, SaslMechanism};