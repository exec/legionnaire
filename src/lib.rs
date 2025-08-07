pub mod client;
pub mod connection;
pub mod connection_manager;
pub mod reliable_client;
// pub mod message; // Now using iron-protocol
// pub mod capabilities; // Now using iron-protocol
pub mod auth;
pub mod error;
pub mod logger;
pub mod ui;
// pub mod tui_simple; // Original with borrow checker issues
pub mod tui; // New working TUI
pub mod config;
pub mod dos_protection;

pub use client::IronClient;
pub use reliable_client::ReliableIronClient;
pub use error::{IronError, ConnectionState, DisconnectReason};
pub use ui::IrcUi;
pub use tui::IrcTui; // Use new working TUI
pub use config::Config;
pub use dos_protection::DosProtection;

// Re-export iron-protocol types for convenience
pub use iron_protocol::{
    IrcMessage, Command, Capability, CapabilitySet, CapabilityHandler,
    MessageReaction, ReactionAction, MessageReply,
    constants, utils
};
pub use iron_protocol::sasl::{SaslAuth, SaslMechanism};