pub mod client;
pub mod connection;
pub mod message;
pub mod capabilities;
pub mod auth;
pub mod error;
pub mod ui;
// pub mod tui_simple; // Original with borrow checker issues
pub mod tui; // New working TUI
pub mod config;

pub use client::IronClient;
pub use error::IronError;
pub use ui::IrcUi;
pub use tui::IrcTui; // Use new working TUI
pub use config::Config;