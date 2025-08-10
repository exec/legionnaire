use crate::client::IronClient;
use legion_protocol::IrcMessage;
use crate::error::Result;
use crate::config::{Config, KeybindingsConfig};
use crate::{iron_debug, iron_info, iron_warn, iron_error};

use std::collections::HashMap;
use std::time::SystemTime;
use std::io::{self, Write};
use std::fs::OpenOptions;
use regex::Regex;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};

use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use futures::StreamExt;

pub struct IrcTui {
    client: IronClient,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    
    // Channel state
    channels: HashMap<String, ChannelData>,
    channel_order: Vec<String>,
    current_tab: usize,
    message_scroll: usize,
    selected_message_index: Option<usize>,  // Index of currently selected message (from bottom)
    reply_to_message_id: Option<String>,     // ID of message we're replying to (for IRCv3 +draft/reply)
    
    // Input state
    input: String,
    input_cursor: usize,
    tab_completion_state: Option<TabCompletionState>,
    
    // UI state
    show_help: bool,
    show_sidebar: bool,
    focus_mode: FocusMode,  // Current focus area
    sidebar_selection: usize,  // Index in combined sidebar list
    previous_sidebar_selection: usize,  // Previous position before jumping to send button
    channel_users_expanded: HashMap<String, bool>,  // Track which channels have users expanded
    running: bool,
    user_context_menu: Option<UserContextMenu>,  // Active user context menu
    message_context_menu: Option<MessageContextMenu>,  // Active message context menu
    reaction_modal: Option<ReactionModal>,  // Active reaction modal
    whois_modal: Option<WhoisModal>,  // Active WHOIS modal
    emoji_picker: Option<EmojiPicker>,  // Active emoji picker
    pending_auto_join_done: bool,  // Flag to track if auto-join has been processed
    
    // Config
    keybindings: KeybindingsConfig,
    
    // Logging
    log_file: Option<std::fs::File>,
    
    // History batch tracking
    current_batch: Option<String>, // Current BATCH reference ID
    current_batch_type: Option<String>, // Current BATCH type
    current_batch_target: Option<String>, // Target channel/user for current batch
    
    // Configuration
    config: Config,
}

#[derive(Debug, Clone)]
struct ChannelData {
    name: String,
    messages: Vec<DisplayMessage>,
    users: Vec<String>,
    users_expanded: bool,  // Whether users are shown for this channel
    topic: Option<String>,
    unread_count: usize,
    activity: ActivityLevel,
    // History management
    history_loaded: bool,    // Whether we've loaded initial history
    loading_history: bool,   // Whether we're currently loading history
    oldest_message_id: Option<String>, // ID of oldest message (for loading more)
    can_load_more: bool,     // Whether more history is available
}

#[derive(Debug, Clone)]
struct DisplayMessage {
    timestamp: SystemTime,
    sender: Option<String>,
    content: String,
    message_type: MessageType,
    message_id: Option<String>, // IRCv3 message ID for reactions/replies
    reactions: Vec<(String, usize)>, // (emoji, count) pairs
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
enum ActivityLevel {
    None,
    Message,
    Mention,
}

#[derive(Debug, Clone)]
enum MessageType {
    Privmsg,
    Notice,
    Join,
    Part,
    Topic,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FocusMode {
    Sidebar,
    Input,
}

#[derive(Debug, Clone)]
struct TabCompletionState {
    original_input: String,
    original_cursor: usize,
    completions: Vec<String>,
    current_index: usize,
    completion_start: usize,
}

#[derive(Debug, Clone)]
enum SidebarItemType {
    ChannelsHeader,
    Channel(usize),
    UsersHeader,
    User(usize),
    Spacing,
}

#[derive(Debug, Clone)]
struct UserContextMenu {
    username: String,
    channel: String,
    selected_option: usize,
    options: Vec<UserAction>,
}

#[derive(Debug, Clone)]
enum UserAction {
    Query,
    Whois,
    Kick,
    Ban,
    Op,
    Deop,
    Cancel,
}

#[derive(Debug, Clone)]
struct MessageContextMenu {
    message_id: String,
    message_author: String,
    message_content: String,
    selected_option: usize,
    options: Vec<MessageAction>,
}

#[derive(Debug, Clone)]
struct ReactionModal {
    message_id: String,
    message_author: String,
    reactions: Vec<(String, Vec<String>)>, // (emoji, users_who_reacted)
}

#[derive(Debug, Clone)]
struct WhoisModal {
    nick: String,
    user_info: Option<String>, // user@host (realname)
    server_info: Option<String>, // server info
    operator: bool,
    idle_info: Option<String>, // idle time and signon
    channels: Option<String>, // channels
    end_received: bool, // whether 318 (end of whois) was received
}

#[derive(Debug, Clone)]
enum MessageAction {
    Reply,
    React,
    ViewReactions,
    Quote,
    Copy,
    Cancel,
}

#[derive(Debug, Clone)]
struct EmojiPicker {
    message_id: String,
    channel: String,
    selected_index: usize,
    search_query: String,
    filtered_emojis: Vec<(&'static str, &'static str)>,
    all_emojis: Vec<(&'static str, &'static str)>,
}

impl EmojiPicker {
    fn new(message_id: String, channel: String) -> Self {
        iron_debug!("emoji_picker", "Creating new EmojiPicker for message_id: {}, channel: {}", message_id, channel);
        
        let all_emojis = vec![
            ("👍", "Thumbs Up"),
            ("👎", "Thumbs Down"),
            ("❤️", "Heart"),
            ("😀", "Happy"),
            ("😂", "Laughing"),
            ("😎", "Cool"),
            ("👀", "Eyes"),
            ("🔥", "Fire"),
            ("🎉", "Party"),
            ("✅", "Check"),
            ("❌", "X"),
            ("💯", "100"),
            ("🤔", "Thinking"),
            ("👏", "Clap"),
            ("🙏", "Pray"),
            ("😭", "Crying"),
            ("😡", "Angry"),
            ("🤯", "Mind Blown"),
            ("🚀", "Rocket"),
            ("💻", "Computer"),
            ("🐛", "Bug"),
            ("📝", "Memo"),
            ("⭐", "Star"),
            ("💎", "Diamond"),
            ("🎯", "Target"),
        ];
        
        let mut picker = Self {
            message_id,
            channel,
            selected_index: 0,
            search_query: String::new(),
            filtered_emojis: all_emojis.clone(),
            all_emojis,
        };
        picker.update_filter();
        picker
    }

    fn update_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_emojis = self.all_emojis.clone();
        } else {
            let query = self.search_query.to_lowercase();
            self.filtered_emojis = self.all_emojis
                .iter()
                .filter(|(_, name)| name.to_lowercase().contains(&query))
                .copied()
                .collect();
        }
        // Reset selection if it's out of bounds
        if self.selected_index >= self.filtered_emojis.len() && !self.filtered_emojis.is_empty() {
            self.selected_index = 0;
        }
    }
}

impl IrcTui {
    pub fn new(client: IronClient, config: &Config) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Skip EnableMouseCapture to allow text selection on macOS
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            client,
            terminal,
            channels: HashMap::new(),
            channel_order: Vec::new(),
            current_tab: 0,
            message_scroll: 0,
            selected_message_index: None,
            reply_to_message_id: None,
            input: String::new(),
            input_cursor: 0,
            tab_completion_state: None,
            show_help: false,
            show_sidebar: true,
            focus_mode: FocusMode::Input,
            sidebar_selection: 0,
            previous_sidebar_selection: 0,
            channel_users_expanded: HashMap::new(),
            running: false,
            user_context_menu: None,
            message_context_menu: None,
            reaction_modal: None,
            whois_modal: None,
            emoji_picker: None,
            pending_auto_join_done: false,
            keybindings: config.keybindings.clone(),
            log_file: None,
            // History batch tracking
            current_batch: None,
            current_batch_type: None,
            current_batch_target: None,
            // Configuration
            config: config.clone(),
        })
    }

    pub fn new_connected(client: IronClient, config: &Config) -> Result<Self> {
        // Enable raw mode - ignore errors as TUI may still work in some environments
        let _ = enable_raw_mode();
        
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Skip EnableMouseCapture to allow text selection on macOS
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Force complete screen clear to hide any previous debug output
        terminal.clear()?;
        
        let mut tui = Self {
            client,
            terminal,
            channels: HashMap::new(),
            channel_order: Vec::new(),
            current_tab: 0,
            message_scroll: 0,
            selected_message_index: None,
            reply_to_message_id: None,
            input: String::new(),
            input_cursor: 0,
            tab_completion_state: None,
            show_help: false,
            show_sidebar: true,
            focus_mode: FocusMode::Input,
            sidebar_selection: 0,
            previous_sidebar_selection: 0,
            channel_users_expanded: HashMap::new(),
            running: false,
            user_context_menu: None,
            message_context_menu: None,
            reaction_modal: None,
            whois_modal: None,
            emoji_picker: None,
            pending_auto_join_done: false,
            keybindings: config.keybindings.clone(),
            log_file: None,
            // History batch tracking
            current_batch: None,
            current_batch_type: None,
            current_batch_target: None,
            // Configuration
            config: config.clone(),
        };
        
        // Force immediate draw to completely take over display and hide any log bleed-through
        tui.draw()?;
        tui.draw()?; // Double draw to ensure complete takeover
        
        // NUCLEAR OPTION: Completely silence stderr to prevent ANY console bleeding
        unsafe {
            let dev_null = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_WRONLY);
            if dev_null >= 0 {
                libc::dup2(dev_null, libc::STDERR_FILENO);
                libc::close(dev_null);
            }
        }
        
        Ok(tui)
    }

    pub async fn start(&mut self) -> Result<()> {
        iron_info!("tui", "Starting IronChat TUI");
        self.running = true;

        // Connect to IRC
        self.client.connect().await?;
        
        // Create initial server tab
        self.add_channel("Server".to_string());
        self.add_system_message("Connected to IRC server");
        self.add_system_message(&format!("Keys: {} for help, {} for sidebar, {} to quit", 
            self.keybindings.toggle_help, self.keybindings.toggle_users, self.keybindings.quit));
            
        // Add a delayed task to show capabilities after registration
        iron_debug!("tui_start", "TUI started, will show capabilities after registration");

        // Create event stream
        let mut event_stream = EventStream::new();

        // Main event loop with error recovery
        let loop_result = async {
            while self.running {
                // Draw the UI - this is the key fix for borrow checker
                self.draw()?;

                // Handle events
                tokio::select! {
                    // Handle IRC messages
                    message_result = self.client.read_message() => {
                        match message_result {
                            Ok(Some(message)) => {
                                if let Err(e) = self.handle_irc_message(message).await {
                                    iron_error!("tui", "Error handling IRC message: {}", e);
                                }
                            }
                            Ok(None) => {
                                iron_info!("tui", "Connection closed by server");
                                break;
                            }
                            Err(e) => {
                                iron_error!("tui", "Error reading message: {}", e);
                                break;
                            }
                        }
                    }
                    
                    // Handle keyboard events
                    maybe_event = event_stream.next() => {
                        match maybe_event {
                            Some(Ok(event)) => {
                                if let Err(e) = self.handle_event(event).await {
                                    iron_error!("tui", "Error handling event: {}", e);
                                }
                            }
                            Some(Err(e)) => {
                                iron_error!("tui", "Error reading event: {}", e);
                            }
                            None => break,
                        }
                    }
                }
                
            }
            Ok::<(), crate::error::IronError>(())
        }.await;

        // Always cleanup regardless of loop result
        if let Err(cleanup_err) = self.cleanup() {
            iron_error!("tui", "Failed to cleanup TUI: {}", cleanup_err);
        }
        
        // Return the original error if loop failed
        loop_result?;
        Ok(())
    }

    pub async fn start_with_existing_connection(&mut self) -> Result<()> {
        // TUI is active - no more console logging allowed
        self.running = true;

        // Don't connect - connection already established
        
        // Create initial server tab
        self.add_channel("Server".to_string());
        self.add_system_message("Connected to IRC server");
        self.add_system_message(&format!("Keys: {} for help, {} for sidebar, {} to quit", 
            self.keybindings.toggle_help, self.keybindings.toggle_users, self.keybindings.quit));

        // Server tab will contain all server messages and debug logs
        self.add_system_message("TUI initialized - all debug messages will appear here");
        
        // Show capabilities if available
        let capabilities = self.client.get_enabled_capabilities();
        if !capabilities.is_empty() {
            self.add_message("Server", None, "─── IRCv3 Capabilities ───".to_string(), MessageType::Notice);
            for cap in capabilities {
                self.add_message("Server", None, format!("  {}", cap), MessageType::Notice);
            }
        } else {
            self.add_message("Server", None, "No IRCv3 capabilities enabled".to_string(), MessageType::Notice);
        }

        // Setup file logging to ~/.legionnaire.log
        self.setup_file_logging();

        // Handle auto-join channels after TUI is ready
        self.handle_pending_auto_join().await?;

        // Create event stream
        let mut event_stream = EventStream::new();
        let mut message_count = 0u64;
        let mut last_message_time = std::time::Instant::now();
        let start_time = std::time::Instant::now();

        // Main event loop with error recovery
        let loop_result = async {
            while self.running {
                std::fs::write("/tmp/tui_loop_debug.log", format!("TUI loop iteration at {}\n", chrono::Utc::now())).unwrap_or(());
                
                // Draw the UI - this is the key fix for borrow checker
                if let Err(e) = self.draw() {
                    iron_error!("tui", "🎨 Draw error: {}", e);
                    return Err(e);
                }

                // Handle auto-join on first loop iteration (after TUI is fully ready)
                if !self.pending_auto_join_done {
                    let pending_channels = self.client.get_pending_auto_join();
                    if !pending_channels.is_empty() {
                        self.add_system_message(&format!("Auto-joining {} channels...", pending_channels.len()));
                        for channel in pending_channels {
                            iron_info!("tui", "Auto-joining channel: {}", channel);
                            self.add_system_message(&format!("Auto-joining {}", channel));
                            
                            if let Err(e) = self.client.join_channel(&channel).await {
                                iron_error!("tui", "Failed to auto-join {}: {}", channel, e);
                                self.add_system_message(&format!("Failed to auto-join {}: {}", channel, e));
                            } else {
                                iron_debug!("tui", "Auto-join command sent for {} in main loop", channel);
                            }
                        }
                    }
                    self.pending_auto_join_done = true;
                }

                std::fs::write("/tmp/tui_select_debug.log", format!("About to enter tokio::select! at {}\n", chrono::Utc::now())).unwrap_or(());
                // Handle events
                tokio::select! {
                    // Handle IRC messages with timeout
                    message_result = tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        self.client.read_message()
                    ) => {
                        match message_result {
                            Ok(Ok(Some(message))) => {
                                std::fs::write("/tmp/message_received_debug.log", format!("Message received: {}\n", message.command)).unwrap_or(());
                                message_count += 1;
                                let now = std::time::Instant::now();
                                let _since_last = now.duration_since(last_message_time);
                                let _total_elapsed = now.duration_since(start_time);
                                last_message_time = now;
                                
                                // Process message without debug spam
                                
                                // Log the raw message only to file, not to Server tab UI
                                self.add_log_message(&format!("📨 Received: {}", message.to_string().trim()));
                                std::fs::write("/tmp/message_debug.log", format!("Message received: {} at {}\n", message.command, chrono::Utc::now())).unwrap_or(());
                                self.add_system_message(&format!("DEBUG MSG: {}", message.command));
                                
                                if let Err(e) = self.handle_irc_message(message).await {
                                    self.add_log_message(&format!("❌ Error handling message: {}", e));
                                }
                            }
                            Ok(Ok(None)) => {
                                self.add_log_message(&format!("📡 Connection closed by server after {} messages", message_count));
                                break;
                            }
                            Ok(Err(e)) => {
                                self.add_log_message(&format!("❌ Error reading message: {}", e));
                                std::fs::write("/tmp/message_error_debug.log", format!("Error: {}\n", e)).unwrap_or(());
                                // Continue running, don't break on single errors
                            }
                            Err(_timeout) => {
                                // Timeout - this is normal, just continue
                                std::fs::write("/tmp/message_timeout_debug.log", format!("Timeout at {}\n", chrono::Utc::now())).unwrap_or(());
                            }
                        }
                    }
                    
                    // Handle keyboard events
                    maybe_event = event_stream.next() => {
                        match maybe_event {
                            Some(Ok(event)) => {
                                if let Err(e) = self.handle_event(event).await {
                                    self.add_log_message(&format!("❌ Error handling keyboard event: {}", e));
                                }
                            }
                            Some(Err(e)) => {
                                self.add_log_message(&format!("❌ Error reading keyboard event: {}", e));
                            }
                            None => {
                                break;
                            }
                        }
                    }
                    
                    // Add timeout to detect hangs in remote server scenarios
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                        // Heartbeat - TUI still responsive
                    }
                }
                
            }
            Ok::<(), crate::error::IronError>(())
        }.await;

        // Always cleanup regardless of loop result
        if let Err(cleanup_err) = self.cleanup() {
            iron_error!("tui", "Failed to cleanup TUI: {}", cleanup_err);
        }
        
        // Return the original error if loop failed
        loop_result?;
        Ok(())
    }

    fn draw(&mut self) -> Result<()> {
        // Clone all the data we need for drawing to avoid borrowing issues
        let channels = self.channels.clone();
        let channel_order = self.channel_order.clone();
        let current_tab = self.current_tab;
        let message_scroll = self.message_scroll;
        let input = self.input.clone();
        let input_cursor = self.input_cursor;
        let show_help = self.show_help;
        let show_sidebar = self.show_sidebar;
        let sidebar_selection = self.sidebar_selection;
        let focus_mode = self.focus_mode.clone();
        let user_context_menu = self.user_context_menu.clone();
        let keybindings = self.keybindings.clone();
        let selected_message_index = self.selected_message_index;
        let message_context_menu = self.message_context_menu.clone();
        let emoji_picker = self.emoji_picker.clone();

        self.terminal.draw(|f| {
            Self::draw_ui(f, &channels, &channel_order, current_tab, message_scroll, &input, input_cursor, show_help, show_sidebar, sidebar_selection, focus_mode, &user_context_menu, &keybindings, selected_message_index, &message_context_menu, &self.reaction_modal, &self.whois_modal, &emoji_picker);
        })?;
        Ok(())
    }

    fn draw_ui(
        f: &mut Frame,
        channels: &HashMap<String, ChannelData>,
        channel_order: &[String],
        current_tab: usize,
        message_scroll: usize,
        input: &str,
        input_cursor: usize,
        show_help: bool,
        show_sidebar: bool,
        sidebar_selection: usize,
        focus_mode: FocusMode,
        user_context_menu: &Option<UserContextMenu>,
        keybindings: &KeybindingsConfig,
        selected_message_index: Option<usize>,
        message_context_menu: &Option<MessageContextMenu>,
        reaction_modal: &Option<ReactionModal>,
        whois_modal: &Option<WhoisModal>,
        emoji_picker: &Option<EmojiPicker>,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),    // Main area
                Constraint::Length(3), // Input
            ])
            .split(f.size());

        // Split main area horizontally if sidebar is shown
        let main_chunks = if show_sidebar {
            let layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(75), Constraint::Percentage(25)])
                .split(chunks[0]);
            layout.to_vec()
        } else {
            vec![chunks[0]]
        };

        // Draw messages
        Self::draw_messages(f, main_chunks[0], channels, channel_order, current_tab, message_scroll, focus_mode, selected_message_index);

        // Draw sidebar if enabled
        if show_sidebar && main_chunks.len() > 1 {
            Self::draw_sidebar(f, main_chunks[1], channels, channel_order, current_tab, sidebar_selection, focus_mode);
        }

        // Draw input
        Self::draw_input(f, chunks[1], input, input_cursor);

        // Draw help overlay if enabled
        if show_help {
            Self::draw_help(f, keybindings);
        }
        
        // Draw user context menu if active
        if let Some(ref menu) = user_context_menu {
            Self::draw_user_context_menu(f, menu);
        }

        // Draw message context menu if active
        if let Some(ref menu) = message_context_menu {
            Self::draw_message_context_menu(f, menu);
        }
        
        // Draw reaction modal if active
        if let Some(ref modal) = reaction_modal {
            Self::draw_reaction_modal(f, modal);
        }
        
        // Draw WHOIS modal if active
        if let Some(ref modal) = whois_modal {
            Self::draw_whois_modal(f, modal);
        }
        
        // Draw emoji picker if active
        if let Some(ref picker) = emoji_picker {
            iron_debug!("rendering", "Drawing emoji picker");
            Self::draw_emoji_picker(f, picker);
        }
    }

    fn draw_sidebar(
        f: &mut Frame,
        area: Rect,
        channels: &HashMap<String, ChannelData>,
        channel_order: &[String],
        current_tab: usize,
        sidebar_selection: usize,
        focus_mode: FocusMode,
    ) {
        let mut items = Vec::new();
        let mut item_index = 0;
        
        // Separate channels and users
        let (channels_list, users_list): (Vec<_>, Vec<_>) = channel_order.iter()
            .enumerate()
            .partition(|(_, name)| name.starts_with('#') || name == &"Server");
        
        // Add channels section
        if !channels_list.is_empty() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("Channels", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            ])));
            
            // Add each channel
            for (i, chan_name) in channels_list {
                item_index += 1;
                let is_selected = focus_mode == FocusMode::Sidebar && item_index == sidebar_selection;
                let is_current = i == current_tab;
                
                let channel = &channels[chan_name];
                let style = if is_current {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    match channel.activity {
                        ActivityLevel::Mention => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ActivityLevel::Message => Style::default().fg(Color::White),
                        ActivityLevel::None => Style::default().fg(Color::White),
                }
            };
            
                let text = if channel.unread_count > 0 && i != current_tab {
                    format!(" {} ({})", chan_name, channel.unread_count)
                } else {
                    format!(" {}", chan_name)
                };
                
                let mut item = ListItem::new(text);
                if is_selected {
                    item = item.style(style.bg(Color::DarkGray));
                } else {
                    item = item.style(style);
                }
                items.push(item);
            }
        }
        
        // Add Users section
        if !users_list.is_empty() {
            // Add spacing
            item_index += 1;
            items.push(ListItem::new(""));
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled("Users", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            ])));
            
            // Add each user
            for (i, user_name) in users_list {
                item_index += 1;
                let is_selected = focus_mode == FocusMode::Sidebar && item_index == sidebar_selection;
                let is_current = i == current_tab;
                
                let channel = &channels[user_name];
                let style = if is_current {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    match channel.activity {
                        ActivityLevel::Mention => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ActivityLevel::Message => Style::default().fg(Color::White),
                        ActivityLevel::None => Style::default().fg(Color::White),
                    }
                };
                
                let text = if channel.unread_count > 0 && i != current_tab {
                    format!(" {} ({})", user_name, channel.unread_count)
                } else {
                    format!(" {}", user_name)
                };
                
                let mut item = ListItem::new(text);
                if is_selected {
                    item = item.style(style.bg(Color::DarkGray));
                } else {
                    item = item.style(style);
                }
                items.push(item);
            }
        }
        
        // Add current channel users section if it has users
        if let Some(current_chan_name) = channel_order.get(current_tab) {
            if let Some(channel) = channels.get(current_chan_name) {
                if !channel.users.is_empty() {
                    // Add spacing
                    item_index += 1;
                    items.push(ListItem::new(""));
                    
                    item_index += 1;
                    let is_selected = focus_mode == FocusMode::Sidebar && item_index == sidebar_selection;
                    let expanded = channel.users_expanded;
                    
                    // Users header with expand/collapse indicator
                    let indicator = if expanded { "▼" } else { "▶" };
                    let user_count = channel.users.len();
                    let header_text = format!("{} Channel Users ({})", indicator, user_count);
                    
                    let mut header_item = ListItem::new(Line::from(vec![
                        Span::styled(header_text, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    ]));
                    
                    if is_selected {
                        header_item = header_item.style(Style::default().bg(Color::DarkGray));
                    }
                    items.push(header_item);
                    
                    // Only show users if expanded
                    if expanded {
                        for user in &channel.users {
                            item_index += 1;
                            let is_selected = focus_mode == FocusMode::Sidebar && item_index == sidebar_selection;
                            
                            let prefix = if user.starts_with('@') {
                                "@"
                            } else if user.starts_with('+') {
                                "+"
                            } else {
                                " "
                            };
                            
                            let nick = user.trim_start_matches('@').trim_start_matches('+');
                            let text = format!("  {}{}", prefix, nick);  // Extra indent for users
                            
                            let mut item = ListItem::new(text);
                            if is_selected {
                                item = item.style(Style::default().bg(Color::DarkGray));
                            }
                            items.push(item);
                        }
                    }
                }
            }
        }
        
        let list = List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Sidebar")
                .border_style(
                    if focus_mode == FocusMode::Sidebar {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    }
                ));
        
        f.render_widget(list, area);
    }

    fn draw_messages(
        f: &mut Frame,
        area: Rect,
        channels: &HashMap<String, ChannelData>,
        channel_order: &[String],
        current_tab: usize,
        scroll_offset: usize,
        focus_mode: FocusMode,
        selected_message_index: Option<usize>,
    ) {
        let current_channel = channel_order.get(current_tab)
            .and_then(|name| channels.get(name));
        
        let messages: Vec<ListItem> = if let Some(channel) = current_channel {
            let total_messages = channel.messages.len();
            let visible_height = area.height.saturating_sub(2) as usize; // Subtract border height
            
            if total_messages == 0 {
                vec![]
            } else {
                // Calculate which messages to show based on scroll
                // scroll_offset = 0 means we're at the bottom (newest messages)
                // scroll_offset = total_messages means we're at the top (oldest messages)
                let end_index = total_messages.saturating_sub(scroll_offset);
                let start_index = if end_index > visible_height {
                    end_index - visible_height
                } else {
                    0  // Show from the beginning if we don't have enough messages
                };
                
                // Ensure we have valid indices
                let safe_end = end_index.min(total_messages);
                let safe_start = start_index.min(safe_end);
                
                channel.messages[safe_start..safe_end].iter()
                    .enumerate()
                    .map(|(relative_index, msg)| {
                        let global_index = safe_start + relative_index;
                        let message_text = Self::format_message(msg);
                        
                        // Check if this message is selected (convert from bottom-up indexing)
                        let from_bottom_index = total_messages.saturating_sub(1).saturating_sub(global_index);
                        let is_selected = selected_message_index == Some(from_bottom_index);
                        
                        if is_selected {
                            // Highlight selected message with different style
                            ListItem::new(message_text).style(Style::default().bg(Color::Blue).fg(Color::White))
                        } else {
                            ListItem::new(message_text)
                        }
                    })
                    .collect()
            }
        } else {
            vec![]
        };

        let title = if let Some(channel) = current_channel {
            let topic = channel.topic.as_ref()
                .map(|t| format!(" - {}", t))
                .unwrap_or_default();
            format!("{}{}", channel.name, topic)
        } else {
            "No Channel".to_string()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(
                if focus_mode == FocusMode::Input {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            );

        let messages_list = List::new(messages)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(messages_list, area);
    }


    fn draw_input(f: &mut Frame, area: Rect, input: &str, input_cursor: usize) {
        // Draw input field
        let input_widget = Paragraph::new(input)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Input (Press Enter to send)")
                .border_style(Style::default().fg(Color::DarkGray)));
        
        f.render_widget(input_widget, area);
        
        // Show cursor in input field
        f.set_cursor(
            area.x + input_cursor as u16 + 1,
            area.y + 1,
        );
    }

    fn draw_user_context_menu(f: &mut Frame, menu: &UserContextMenu) {
        // Create a popup in the center
        let popup_width = 24;
        let popup_height = menu.options.len() as u16 + 4; // +4 for borders and title
        let area = Rect {
            x: (f.size().width.saturating_sub(popup_width)) / 2,
            y: (f.size().height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        // Clear the background
        f.render_widget(Clear, area);

        // Create menu items
        let menu_items: Vec<ListItem> = menu.options.iter().enumerate().map(|(i, action)| {
            let text = match action {
                UserAction::Query => "💬 Query",
                UserAction::Whois => "❓ WHOIS",
                UserAction::Kick => "🦵 Kick",
                UserAction::Ban => "🚫 Ban",
                UserAction::Op => "👑 Give Op",
                UserAction::Deop => "👑 Remove Op", 
                UserAction::Cancel => "❌ Cancel",
            };

            let style = if i == menu.selected_option {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            ListItem::new(text).style(style)
        }).collect();

        let menu_list = List::new(menu_items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title(format!("User: {}", menu.username))
                .border_style(Style::default().fg(Color::DarkGray)));

        f.render_widget(menu_list, area);
    }

    fn draw_help(f: &mut Frame, keybindings: &KeybindingsConfig) {
        // Center the help dialog properly
        let popup_width = 60;
        let popup_height = 24;
        let area = Rect {
            x: (f.size().width.saturating_sub(popup_width)) / 2,
            y: (f.size().height.saturating_sub(popup_height)) / 2,
            width: popup_width.min(f.size().width),
            height: popup_height.min(f.size().height),
        };

        f.render_widget(Clear, area);

        let help_text = vec![
            Line::from("╔════════════════════════════════════════╗"),
            Line::from("║  ██╗██████╗  ██████╗ ███╗   ██╗       ║"),
            Line::from("║  ██║██╔══██╗██╔═══██╗████╗  ██║       ║"),  
            Line::from("║  ██║██████╔╝██║   ██║██╔██╗ ██║       ║"),
            Line::from("║  ██║██╔══██╗██║   ██║██║╚██╗██║       ║"),
            Line::from("║  ██║██║  ██║╚██████╔╝██║ ╚████║       ║"),
            Line::from("║  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ║"),
            Line::from("║    ╔═╗╦ ╦╔═╗╔╦╗                       ║"),
            Line::from("║    ║  ╠═╣╠═╣ ║   Security-Hardened    ║"),
            Line::from("║    ╚═╝╩ ╩╩ ╩ ╩      IRCv3 Client      ║"),
            Line::from("╚════════════════════════════════════════╝"),
            Line::from(""),
            Line::from("Navigation:"),
            Line::from("  Up/Down - Navigate sidebar OR select messages"),
            Line::from("  Enter - Select channel/user OR show message context menu"),
            Line::from("  Esc - Clear message selection"),
            Line::from("  Tab - Auto-complete nicknames/commands"),
            Line::from(""),
            Line::from("Commands:"),
            Line::from("  /join <channel>  - Join channel"),
            Line::from("  /part [channel]  - Leave channel"),
            Line::from("  /nick <nick>     - Change nickname"),
            Line::from("  /msg <user> <msg> - Private message"),
            Line::from("  /ns <cmd>        - NickServ command"),
            Line::from("  /cs <cmd>        - ChanServ command"),
            Line::from("  /quit [reason]   - Quit IRC"),
            Line::from(""),
            Line::from("IRCv3 Features:"),
            Line::from("  🔐 SASL Authentication"),
            Line::from("  ⏰ Server-time (precise timestamps)"),
            Line::from("  🏷️ Message-tags support"),
            Line::from("  💤 Away-notify (real-time away status)"),
            Line::from("  🔒 STS (Strict Transport Security)"),
            Line::from(""),
            Line::from("Keys:"),
            Line::from(format!("  {} - Toggle this help", keybindings.toggle_help)),
            Line::from(format!("  {} - Toggle sidebar", keybindings.toggle_users)),
            Line::from(format!("  {} - Quit", keybindings.quit)),
        ];

        let help = Paragraph::new(help_text)
            .block(Block::default().title("Help").borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)))
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: true });

        f.render_widget(help, area);
    }

    fn draw_emoji_picker(f: &mut Frame, picker: &EmojiPicker) {
        // Create a popup for emoji selection
        let popup_width = 40;
        let popup_height = 20;
        let area = Rect {
            x: (f.size().width.saturating_sub(popup_width)) / 2,
            y: (f.size().height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        // Clear the background
        f.render_widget(Clear, area);

        // Split area for search box and emoji list
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Search box
                Constraint::Min(1),    // Emoji list
            ])
            .split(area);

        // Draw search box
        let search_widget = Paragraph::new(picker.search_query.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Search Emojis")
                .border_style(Style::default().fg(Color::Cyan)));
        f.render_widget(search_widget, chunks[0]);
        
        // Show cursor in search box
        f.set_cursor(
            chunks[0].x + picker.search_query.len() as u16 + 1,
            chunks[0].y + 1,
        );

        // Draw emoji list
        let emoji_items: Vec<ListItem> = picker.filtered_emojis.iter().enumerate().map(|(i, &(emoji, name))| {
            let text = format!("{} {}", emoji, name);
            let style = if i == picker.selected_index {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(text).style(style)
        }).collect();

        let emoji_list = List::new(emoji_items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Select Emoji (Enter to send, Esc to cancel)")
                .border_style(Style::default().fg(Color::DarkGray)));

        f.render_widget(emoji_list, chunks[1]);
    }

    fn draw_message_context_menu(f: &mut Frame, menu: &MessageContextMenu) {
        // Create a popup in the center
        let popup_width = 28;
        let popup_height = menu.options.len() as u16 + 4; // +4 for borders and title
        let area = Rect {
            x: (f.size().width.saturating_sub(popup_width)) / 2,
            y: (f.size().height.saturating_sub(popup_height)) / 2,
            width: popup_width,
            height: popup_height,
        };

        // Clear the background
        f.render_widget(Clear, area);

        // Create menu items
        let menu_items: Vec<ListItem> = menu.options.iter().enumerate().map(|(i, action)| {
            let text = match action {
                MessageAction::Reply => "↩️  Reply to message",
                MessageAction::React => "😀 React to message", 
                MessageAction::ViewReactions => "👀 View reactions",
                MessageAction::Quote => "📝 Quote message",
                MessageAction::Copy => "📋 Copy message",
                MessageAction::Cancel => "❌ Cancel",
            };

            let style = if i == menu.selected_option {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            ListItem::new(text).style(style)
        }).collect();

        let menu_list = List::new(menu_items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title(format!("Message: {}", menu.message_author))
                .border_style(Style::default().fg(Color::DarkGray)));

        f.render_widget(menu_list, area);
    }

    fn draw_reaction_modal(f: &mut Frame, modal: &ReactionModal) {
        // Create a modal in the center
        let popup_width = 50;
        let popup_height = if modal.reactions.is_empty() { 5 } else { 8 + modal.reactions.len() * 2 };
        
        let area = f.size();
        let popup_area = Rect {
            x: (area.width.saturating_sub(popup_width)) / 2,
            y: (area.height.saturating_sub(popup_height as u16)) / 2,
            width: popup_width.min(area.width),
            height: popup_height.min(area.height as usize) as u16,
        };

        // Clear the area
        f.render_widget(Clear, popup_area);

        // Create content based on reactions
        let content = if modal.reactions.is_empty() {
            vec![
                Line::from(vec![
                    Span::styled(
                        format!("No reactions on message from {}", modal.message_author),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    )
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "Press any key to close",
                        Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)
                    )
                ])
            ]
        } else {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(
                        format!("Reactions on message from {}", modal.message_author),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    )
                ]),
                Line::from("")
            ];
            
            for (emoji, users) in &modal.reactions {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ", emoji),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    ),
                    Span::styled(
                        format!("({} reaction{})", users.len(), if users.len() == 1 { "" } else { "s" }),
                        Style::default().fg(Color::Green)
                    )
                ]));
                
                // Show users who reacted
                let users_str = if users.len() <= 5 {
                    users.join(", ")
                } else {
                    format!("{}, and {} more", users[..3].join(", "), users.len() - 3)
                };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(users_str, Style::default().fg(Color::Cyan))
                ]));
            }
            
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "Press any key to close",
                    Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)
                )
            ]));
            
            lines
        };

        let paragraph = Paragraph::new(content)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Reactions")
                .title_alignment(ratatui::layout::Alignment::Center)
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::Black))
            )
            .alignment(ratatui::layout::Alignment::Left)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, popup_area);
    }

    fn draw_whois_modal(f: &mut Frame, modal: &WhoisModal) {
        // Create a modal in the center
        let popup_width = 60;
        let mut content_lines = 3; // Title, blank line, close instruction
        
        // Count lines needed for content
        if modal.user_info.is_some() { content_lines += 1; }
        if modal.server_info.is_some() { content_lines += 1; }
        if modal.operator { content_lines += 1; }
        if modal.idle_info.is_some() { content_lines += 1; }
        if modal.channels.is_some() { content_lines += 1; }
        
        let popup_height = content_lines + 2; // +2 for borders
        
        let area = f.size();
        let popup_area = Rect {
            x: (area.width.saturating_sub(popup_width)) / 2,
            y: (area.height.saturating_sub(popup_height as u16)) / 2,
            width: popup_width.min(area.width),
            height: popup_height.min(area.height as usize) as u16,
        };
        
        // Clear the area
        f.render_widget(Clear, popup_area);
        
        // Build content
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    format!("WHOIS Information - {}", modal.nick),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                )
            ]),
            Line::from("")
        ];
        
        if let Some(ref user_info) = modal.user_info {
            lines.push(Line::from(vec![
                Span::styled("User: ", Style::default().fg(Color::Green)),
                Span::raw(user_info)
            ]));
        }
        
        if let Some(ref server_info) = modal.server_info {
            lines.push(Line::from(vec![
                Span::styled("Server: ", Style::default().fg(Color::Green)),
                Span::raw(server_info)
            ]));
        }
        
        if modal.operator {
            lines.push(Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::Green)),
                Span::styled("IRC Operator", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            ]));
        }
        
        if let Some(ref idle_info) = modal.idle_info {
            lines.push(Line::from(vec![
                Span::styled("Idle: ", Style::default().fg(Color::Green)),
                Span::raw(idle_info)
            ]));
        }
        
        if let Some(ref channels) = modal.channels {
            lines.push(Line::from(vec![
                Span::styled("Channels: ", Style::default().fg(Color::Green)),
                Span::raw(channels)
            ]));
        }
        
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                "Press any key to close",
                Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)
            )
        ]));
        
        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .title(" WHOIS ")
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            .alignment(ratatui::layout::Alignment::Left)
            .wrap(Wrap { trim: true });
        
        f.render_widget(paragraph, popup_area);
    }

    fn format_message(msg: &DisplayMessage) -> Text<'static> {
        let timestamp = chrono::DateTime::<chrono::Local>::from(msg.timestamp)
            .format("%H:%M:%S")
            .to_string();

        // Build the main message line with reactions inline
        let mut message_spans = match &msg.message_type {
            MessageType::Privmsg => {
                if let Some(ref sender) = msg.sender {
                    vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled(format!("<{}>", sender), Style::default().fg(Color::Green)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]
                } else {
                    vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]
                }
            }
            MessageType::Notice => {
                if let Some(ref sender) = msg.sender {
                    vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled(format!("-{}-", sender), Style::default().fg(Color::Yellow)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]
                } else {
                    vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled("***", Style::default().fg(Color::Yellow)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]
                }
            }
            _ => {
                vec![
                    Span::styled(timestamp, Style::default().fg(Color::Gray)),
                    Span::raw(" "),
                    Span::styled("***", Style::default().fg(Color::Blue)),
                    Span::raw(" "),
                    Span::raw(msg.content.clone()),
                ]
            }
        };
        
        // Add reactions inline to the right of the message
        if !msg.reactions.is_empty() {
            message_spans.push(Span::raw("  ")); // spacing
            for (emoji, count) in &msg.reactions {
                message_spans.push(Span::styled(
                    format!("[{} {}]", emoji, count), 
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                ));
            }
        }

        Text::from(Line::from(message_spans))
    }

    fn cleanup(&mut self) -> Result<()> {
        // Disconnect from IRC gracefully
        if self.client.is_connected() {
            let _ = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.client.disconnect().await
                })
            });
        }
        
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            // DisableMouseCapture - not used since we don't enable it
        )?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    async fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Press {
                    // Handle context menus and modals first if they're open
                    if self.user_context_menu.is_some() || self.message_context_menu.is_some() {
                        return self.handle_context_menu_key(key.code).await;
                    }
                    
                    // Handle reaction modal if open
                    if self.reaction_modal.is_some() {
                        return self.handle_reaction_modal_key(key.code).await;
                    }
                    
                    // Handle WHOIS modal if open
                    if self.whois_modal.is_some() {
                        return self.handle_whois_modal_key(key.code).await;
                    }
                    
                    // Handle emoji picker if open
                    if self.emoji_picker.is_some() {
                        iron_debug!("key_handling", "Emoji picker is open, delegating to handle_emoji_picker_key");
                        return self.handle_emoji_picker_key(key.code).await;
                    }
                    
                    // Check custom keybindings first
                    if self.keybindings.matches_key(&self.keybindings.quit, key.code, key.modifiers) {
                        self.running = false;
                    } else if self.keybindings.matches_key(&self.keybindings.toggle_help, key.code, key.modifiers) {
                        self.show_help = !self.show_help;
                    } else if self.keybindings.matches_key(&self.keybindings.toggle_users, key.code, key.modifiers) {
                        self.show_sidebar = !self.show_sidebar;
                    } else {
                        // Handle keys based on current focus mode
                        match self.focus_mode {
                            FocusMode::Sidebar => {
                                match key.code {
                                    KeyCode::Up => self.sidebar_up(),
                                    KeyCode::Down => self.sidebar_down(),
                                    KeyCode::Left => {
                                        self.focus_mode = FocusMode::Input;
                                    }
                                    KeyCode::Enter => {
                                        // If input is not empty, send message instead of sidebar select
                                        if !self.input.is_empty() {
                                            if let Err(e) = self.handle_input().await {
                                                iron_error!("tui", "Failed to send message from sidebar: {}", e);
                                            }
                                        } else {
                                            self.sidebar_select();
                                        }
                                    }
                                    KeyCode::Tab => self.handle_tab_completion(),
                                    KeyCode::Char(c) => {
                                        // When typing in sidebar, switch to input and add the character
                                        self.focus_mode = FocusMode::Input;
                                        self.input.insert(self.input_cursor, c);
                                        self.input_cursor += 1;
                                    }
                                    _ => {} // Ignore other keys
                                }
                            }
                            FocusMode::Input => {
                                match key.code {
                                    KeyCode::Right if self.input_cursor == self.input.len() => {
                                        // If at end of input, go to sidebar
                                        self.focus_mode = FocusMode::Sidebar;
                                    }
                                    KeyCode::Up => self.select_previous_message(),  // Select previous message
                                    KeyCode::Down => self.select_next_message(), // Select next message
                                    KeyCode::PageUp => {
                                        // Scroll up and load more history if needed
                                        self.scroll_up().await?;
                                    }
                                    KeyCode::PageDown => {
                                        // Scroll down
                                        self.scroll_down();
                                    }
                                    KeyCode::Home => {
                                        // Go to top and load more history
                                        self.scroll_to_top().await?;
                                    }
                                    KeyCode::End => {
                                        // Go to bottom
                                        self.scroll_to_bottom();
                                    }
                                    KeyCode::Enter if self.selected_message_index.is_some() => self.show_message_context_menu(),
                                    KeyCode::Esc => self.clear_message_selection(),
                                    KeyCode::Tab => self.handle_tab_completion(),
                                    _ => {
                                        // Handle normal input keys
                                        self.handle_input_keys(key.code).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Event::Resize(width, height) => {
                iron_debug!("tui", "Terminal resized to {}x{}", width, height);
                // Ratatui handles the resize automatically, we just need to acknowledge it
                // The next draw() call will adapt to the new size
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_input(&mut self) -> Result<()> {
        let input = self.input.trim().to_string();
        if input.is_empty() {
            return Ok(());
        }

        // Clear tab completion state on input submission
        self.tab_completion_state = None;

        if input.starts_with('/') {
            self.parse_command(&input[1..]).await?;
        } else {
            // Send message to current channel
            if let Some(channel_name) = self.get_current_channel_name() {
                if channel_name != "Server" {
                    // Check if we're replying to a message
                    if let Some(reply_to_id) = &self.reply_to_message_id {
                        // Send IRCv3 reply if server supports it
                        if self.client.is_capability_enabled("+draft/reply") {
                            iron_debug!("reply", "Sending reply to message: {} with text: {}", reply_to_id, input);
                            
                            use legion_protocol::MessageReply;
                            let reply = MessageReply::new(
                                channel_name.clone(),
                                reply_to_id.clone(),
                                input.clone()
                            );
                            
                            let reply_msg = reply.to_message();
                            self.client.send_message(&reply_msg).await?;
                        } else {
                            // Fallback to regular message if server doesn't support replies
                            self.client.send_privmsg(&channel_name, &input).await?;
                        }
                        
                        // Clear reply mode
                        self.reply_to_message_id = None;
                    } else {
                        // Regular message
                        self.client.send_privmsg(&channel_name, &input).await?;
                    }
                    
                    // Only add message locally if server doesn't support echo-message
                    // Otherwise wait for the server to echo it back with proper prefix
                    if !self.client.has_capability("echo-message") {
                        self.add_message(
                            &channel_name,
                            Some(self.client.current_nickname().to_string()),
                            input.clone(),
                            MessageType::Privmsg,
                        );
                    }
                } else {
                    self.add_system_message("Cannot send messages to Server tab. Use /join <channel> first.");
                }
            }
        }

        // Clear input
        self.input.clear();
        self.input_cursor = 0;
        Ok(())
    }

    async fn parse_command(&mut self, input: &str) -> Result<()> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0].to_lowercase().as_str() {
            // Service aliases
            "ns" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /ns <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("NickServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> NickServ: {}", message),
                    MessageType::Notice,
                );
            }
            "cs" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /cs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("ChanServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> ChanServ: {}", message),
                    MessageType::Notice,
                );
            }
            "ms" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /ms <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("MemoServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> MemoServ: {}", message),
                    MessageType::Notice,
                );
            }
            "os" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /os <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("OperServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> OperServ: {}", message),
                    MessageType::Notice,
                );
            }
            "hs" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /hs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("HostServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> HostServ: {}", message),
                    MessageType::Notice,
                );
            }
            "bs" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /bs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                self.client.send_privmsg("BotServ", &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> BotServ: {}", message),
                    MessageType::Notice,
                );
            }
            "join" | "j" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /join <channel>");
                    return Ok(());
                }
                let channel = if parts[1].starts_with('#') {
                    parts[1].to_string()
                } else {
                    format!("#{}", parts[1])
                };
                self.client.join_channel(&channel).await?;
                self.add_system_message(&format!("Joining {}", channel));
            }
            "part" | "leave" => {
                let channel = if parts.len() > 1 {
                    parts[1].to_string()
                } else if let Some(current) = self.get_current_channel_name() {
                    if current == "Server" {
                        self.add_system_message("Cannot part from Server tab");
                        return Ok(());
                    }
                    current
                } else {
                    self.add_system_message("No channel specified and no active channel");
                    return Ok(());
                };
                let reason = if parts.len() > 2 {
                    Some(parts[2..].join(" "))
                } else {
                    None
                };
                self.client.part_channel(&channel, reason.as_deref()).await?;
                self.add_system_message(&format!("Leaving {}", channel));
            }
            "nick" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /nick <nickname>");
                    return Ok(());
                }
                let nick_msg = IrcMessage::new("NICK").with_params(vec![parts[1].to_string()]);
                self.client.send_message(&nick_msg).await?;
                self.add_system_message(&format!("Changing nickname to {}", parts[1]));
            }
            "msg" | "privmsg" => {
                if parts.len() < 3 {
                    self.add_system_message("Usage: /msg <target> <message>");
                    return Ok(());
                }
                let target = parts[1].to_string();
                let message = parts[2..].join(" ");
                self.client.send_privmsg(&target, &message).await?;
                self.add_message(
                    "Server",
                    Some(self.client.current_nickname().to_string()),
                    format!("-> {}: {}", target, message),
                    MessageType::Notice,
                );
            }
            "quit" | "exit" => {
                let reason = if parts.len() > 1 {
                    Some(parts[1..].join(" "))
                } else {
                    None
                };
                if let Some(reason) = reason {
                    self.add_system_message(&format!("Quitting: {}", reason));
                } else {
                    self.add_system_message("Quitting");
                }
                self.running = false;
            }
            "help" | "h" => {
                self.show_help = true;
            }
            "raw" => {
                if parts.len() < 2 {
                    self.add_system_message("Usage: /raw <IRC command>");
                    return Ok(());
                }
                let command = parts[1..].join(" ");
                self.client.send_raw(&command).await?;
                self.add_system_message(&format!("Sent raw: {}", command));
            }
            "history" => {
                if !self.client.has_capability("chathistory") {
                    self.add_system_message("❌ Server does not support CHATHISTORY capability");
                    return Ok(());
                }
                
                let current_channel = self.get_current_channel_name();
                if current_channel.is_none() || current_channel.as_ref().unwrap() == "Server" {
                    self.add_system_message("❌ Cannot load history for Server tab. Switch to a channel first.");
                    return Ok(());
                }
                
                let channel_name = current_channel.unwrap();
                let limit = if parts.len() >= 2 {
                    parts[1].parse::<usize>().unwrap_or(50).min(500)
                } else {
                    50
                };
                
                self.add_system_message(&format!("🕐 Loading {} recent messages for {}...", limit, channel_name));
                
                match self.client.request_recent_history(&channel_name, limit).await {
                    Ok(()) => {
                        // The history will be loaded asynchronously via BATCH responses
                    }
                    Err(e) => {
                        self.add_system_message(&format!("❌ Failed to request history: {}", e));
                    }
                }
            }
            _ => {
                self.add_system_message(&format!("Unknown command: {}. Type /help for available commands.", parts[0]));
            }
        }

        Ok(())
    }

    async fn handle_pending_auto_join(&mut self) -> Result<()> {
        // Auto-join will now be handled in the main event loop to ensure
        // proper timing with message receiving. Just add a system message here.
        iron_debug!("tui", "Auto-join will be processed in main event loop");
        self.add_system_message("TUI initialized - auto-join will be processed shortly");
        Ok(())
    }

    async fn handle_irc_message(&mut self, message: IrcMessage) -> Result<()> {
        // Only log important messages to reduce Server tab noise
        match message.command.as_str() {
            "PRIVMSG" | "NOTICE" | "JOIN" | "PART" | "QUIT" | "NICK" | "KICK" | "MODE" | "TOPIC" => {
                // These are important user-visible events, no need to log them as debug
            }
            _ => {
                iron_debug!("tui", "Received IRC message: {} from {:?}", message.command, message.prefix);
            }
        }

        match message.command.as_str() {
            "BATCH" => {
                if message.params.len() >= 2 {
                    let reference = &message.params[0];
                    let is_start = !reference.starts_with('-');
                    
                    if is_start && message.params.len() >= 2 {
                        let batch_type = &message.params[1];
                        self.handle_history_batch(batch_type, reference, true);
                    } else {
                        self.handle_history_batch("", reference, false);
                    }
                }
                
                // Forward to client
                if let Err(e) = self.client.handle_message(message).await {
                    iron_error!("tui", "Error forwarding BATCH to client: {}", e);
                }
            }
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    let target = &message.params[0];
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Check if this is a private message (target is our nick)
                    let is_private_message = target == self.client.current_nickname();
                    
                    // Extract message ID from IRCv3 tags
                    let message_id = message.get_tag("msgid").and_then(|tag| tag.clone());

                    // Check if this message is part of a CHATHISTORY batch
                    let is_historical = message.get_tag("batch").is_some() && 
                                      self.current_batch_type.as_deref() == Some("chathistory");

                    if is_historical {
                        // This is a historical message from CHATHISTORY
                        iron_debug!("tui", "📜 Historical PRIVMSG from {}: {} (msgid: {:?})", sender, content, message_id);
                        
                        // Set the batch target if not already set
                        if self.current_batch_target.is_none() {
                            self.current_batch_target = Some(target.to_string());
                        }
                        
                        // Use server-provided timestamp or message timestamp
                        let timestamp = message.get_timestamp();
                        
                        if is_private_message {
                            // Private message - create/use user tab
                            self.add_user_tab(sender.to_string());
                            self.add_historical_message(
                                sender,  // Use sender's nick as the tab name
                                Some(sender.to_string()),
                                content.clone(),
                                MessageType::Privmsg,
                                timestamp,
                                message_id,
                            );
                        } else {
                            // Channel message
                            self.add_historical_message(
                                target,
                                Some(sender.to_string()),
                                content.clone(),
                                MessageType::Privmsg,
                                timestamp,
                                message_id,
                            );
                        }
                    } else {
                        // This is a live/current message
                        if is_private_message {
                            // Private message - create/use user tab
                            self.add_user_tab(sender.to_string());
                            self.add_message_with_id(
                                sender,  // Use sender's nick as the tab name
                                Some(sender.to_string()),
                                content.clone(),
                                MessageType::Privmsg,
                                ActivityLevel::Mention,  // Private messages are always high priority
                                message.get_timestamp(),
                                message_id,
                            );
                        } else {
                            // Channel message
                            let is_mention = content.contains(self.client.current_nickname());
                            let activity = if is_mention {
                                ActivityLevel::Mention
                            } else {
                                ActivityLevel::Message
                            };

                            self.add_message_with_id(
                                target,
                                Some(sender.to_string()),
                                content.clone(),
                                MessageType::Privmsg,
                                activity,
                                message.get_timestamp(),
                                message_id,
                            );
                        }
                    }
                }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("server");

                    // Extract message ID from IRCv3 tags
                    let message_id = message.get_tag("msgid").and_then(|tag| tag.clone());

                    self.add_message_with_id(
                        "Server",
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Notice,
                        ActivityLevel::Message,
                        message.get_timestamp(),
                        message_id,
                    );
                }
            }
            "JOIN" => {
                if let Some(channel) = message.params.get(0) {
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Check if this JOIN is from our own nickname
                    let current_nick = self.client.current_nickname().to_string();
                    
                    if sender == current_nick {
                        // This is our own JOIN - add the channel and switch to it
                        self.add_channel(channel.clone());  
                        self.switch_to_channel(channel);
                        self.add_log_message(&format!("✅ Successfully joined channel {}", channel));
                        
                        // Auto-load recent history for the channel if enabled in config
                        let channel_name = channel.clone();
                        if self.should_auto_load_history(&channel_name) {
                            if let Err(e) = self.load_channel_history(&channel_name, 50).await {
                                iron_warn!("tui", "Failed to load history for {}: {}", channel_name, e);
                            }
                        } else {
                            iron_debug!("tui", "Auto-history loading disabled for channel: {}", channel_name);
                        }
                    } else {
                        // This is someone else joining - add them to the channel if it exists
                        if let Some(channel_data) = self.channels.get_mut(channel) {
                            if !channel_data.users.contains(&sender.to_string()) {
                                channel_data.users.push(sender.to_string());
                            }
                        }
                        self.add_log_message(&format!("👋 {} joined {}", sender, channel));
                    }

                    self.add_message(
                        channel,
                        None,
                        format!("{} joined {}", sender, channel),
                        MessageType::Join,
                    );
                }
            }
            "PART" => {
                if let Some(channel) = message.params.get(0) {
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    if sender == self.client.current_nickname() {
                        self.remove_channel(channel);
                    } else {
                        if let Some(channel_data) = self.channels.get_mut(channel) {
                            channel_data.users.retain(|u| u != sender);
                        }
                    }

                    let reason = message.params.get(1).map(|r| format!(" ({})", r)).unwrap_or_default();
                    self.add_message(
                        channel,
                        None,
                        format!("{} left {}{}", sender, channel, reason),
                        MessageType::Part,
                    );
                }
            }
            "AWAY" => {
                // Handle away-notify capability
                if let Some(sender) = message.prefix.as_ref()
                    .and_then(|s| s.split('!').next()) {
                    
                    let away_message = message.params.get(0).cloned().unwrap_or_default();
                    
                    if away_message.is_empty() {
                        // User is back
                        self.add_message(
                            "Server",
                            None,
                            format!("{} is back", sender),
                            MessageType::System,
                        );
                    } else {
                        // User is away
                        self.add_message(
                            "Server",
                            None,
                            format!("{} is away: {}", sender, away_message),
                            MessageType::System,
                        );
                    }
                }
            }
            "QUIT" => {
                if let Some(sender) = message.prefix.as_ref()
                    .and_then(|s| s.split('!').next()) {
                    
                    let reason = message.params.get(0).map(|r| format!(" ({})", r)).unwrap_or_default();
                    
                    // Remove user from all channels
                    for channel_data in self.channels.values_mut() {
                        channel_data.users.retain(|u| u != sender);
                    }
                    
                    self.add_message(
                        "Server",
                        None,
                        format!("{} quit{}", sender, reason),
                        MessageType::System,
                    );
                }
            }
            "NICK" => {
                if let Some(old_nick) = message.prefix.as_ref()
                    .and_then(|s| s.split('!').next()) {
                    
                    if let Some(new_nick) = message.params.get(0) {
                        // Update nick in all channels
                        for channel_data in self.channels.values_mut() {
                            if let Some(pos) = channel_data.users.iter().position(|u| u == old_nick) {
                                channel_data.users[pos] = new_nick.clone();
                            }
                        }
                        
                        self.add_message(
                            "Server",
                            None,
                            format!("{} is now known as {}", old_nick, new_nick),
                            MessageType::System,
                        );
                    }
                }
            }
            "353" => { // NAMES reply
                if message.params.len() >= 4 {
                    let channel = &message.params[2];
                    let names = &message.params[3];
                    
                    if let Some(channel_data) = self.channels.get_mut(channel) {
                        for name in names.split_whitespace() {
                            let clean_name = name.trim_start_matches(['@', '+', '%', '&', '~']);
                            if !channel_data.users.contains(&clean_name.to_string()) {
                                channel_data.users.push(clean_name.to_string());
                            }
                        }
                    }
                }
            }
            "331" => { // No topic
                if message.params.len() >= 2 {
                    let channel = &message.params[1];
                    
                    if let Some(channel_data) = self.channels.get_mut(channel) {
                        channel_data.topic = None;
                    }

                    self.add_message(
                        channel,
                        None,
                        "No topic is set".to_string(),
                        MessageType::Topic,
                    );
                }
            }
            "332" => { // Topic
                if message.params.len() >= 3 {
                    let channel = &message.params[1];
                    let topic = &message.params[2];
                    
                    if let Some(channel_data) = self.channels.get_mut(channel) {
                        channel_data.topic = Some(topic.clone());
                    }

                    self.add_message(
                        channel,
                        None,
                        format!("Topic: {}", topic),
                        MessageType::Topic,
                    );
                }
            }
            "TAGMSG" => {
                // Handle reactions and other tag-only messages
                self.handle_tagmsg(message).await?;
            }
            // WHOIS responses (311-319) - handled in the default case now to avoid duplication
            "PING" | "PONG" | "ERROR" | "433" | "436" => {
                // Forward protocol messages to client for handling
                if let Err(e) = self.client.handle_message(message).await {
                    iron_error!("tui", "Error handling protocol message: {}", e);
                }
            }
            _ => {
                // Handle common server messages that should appear in Server tab
                if message.command.chars().all(|c| c.is_ascii_digit()) {
                    let numeric_code = message.command.as_str();
                    match numeric_code {
                        // Welcome messages
                        "001" | "002" | "003" | "004" | "005" => {
                            if let Some(content) = message.params.last() {
                                self.add_message("Server", None, content.clone(), MessageType::Notice);
                            }
                            
                            // Show capabilities after server features message (005)
                            if numeric_code == "005" {
                                iron_debug!("capability_display", "005 message received, checking capabilities");
                                let capabilities = self.client.get_enabled_capabilities();
                                iron_debug!("capability_display", "Found {} capabilities: {:?}", capabilities.len(), capabilities);
                                if !capabilities.is_empty() {
                                    self.add_message("Server", None, "─── IRCv3 Capabilities ───".to_string(), MessageType::Notice);
                                    for cap in capabilities {
                                        self.add_message("Server", None, format!("  {}", cap), MessageType::Notice);
                                    }
                                } else {
                                    self.add_message("Server", None, "No IRCv3 capabilities enabled".to_string(), MessageType::Notice);
                                }
                            }
                        }
                        // MOTD
                        "372" => { // RPL_MOTD
                            if message.params.len() >= 2 {
                                let motd_line = &message.params[1];
                                self.add_message("Server", None, format!("MOTD: {}", motd_line), MessageType::Notice);
                            }
                        }
                        "375" => { // RPL_MOTDSTART
                            if message.params.len() >= 2 {
                                let motd_start = &message.params[1];
                                self.add_message("Server", None, format!("MOTD: {}", motd_start), MessageType::Notice);
                            }
                        }
                        "376" => { // RPL_ENDOFMOTD
                            if message.params.len() >= 2 {
                                let motd_end = &message.params[1];
                                self.add_message("Server", None, format!("MOTD: {}", motd_end), MessageType::Notice);
                            }
                        }
                        "422" => { // ERR_NOMOTD
                            if message.params.len() >= 2 {
                                let no_motd = &message.params[1];
                                self.add_message("Server", None, format!("MOTD: {}", no_motd), MessageType::Notice);
                            }
                        }
                        // LUSERS
                        "250" | "251" | "252" | "253" | "254" | "255" | "265" | "266" => {
                            if let Some(content) = message.params.last() {
                                self.add_message("Server", None, content.clone(), MessageType::Notice);
                            }
                        }
                        // NAMES (already handled elsewhere, don't show in server)
                        "353" | "366" => {
                            // Skip logging for these
                        }
                        // TOPIC (already handled elsewhere)
                        "332" | "333" => {
                            // Skip logging for these
                        }
                        // LIST
                        "321" | "322" | "323" => {
                            if let Some(content) = message.params.last() {
                                self.add_message("Server", None, content.clone(), MessageType::Notice);
                            }
                        }
                        // WHOIS responses
                        "311" => { // RPL_WHOISUSER
                            if message.params.len() >= 6 {
                                let nick = message.params[1].clone();
                                let user = &message.params[2];
                                let host = &message.params[3];
                                let realname = &message.params[5];
                                
                                let user_info = format!("{}@{} ({})", user, host, realname);
                                
                                // Start or update WHOIS modal
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.user_info = Some(user_info);
                                    }
                                } else {
                                    self.whois_modal = Some(WhoisModal {
                                        nick,
                                        user_info: Some(user_info),
                                        server_info: None,
                                        operator: false,
                                        idle_info: None,
                                        channels: None,
                                        end_received: false,
                                    });
                                }
                            }
                        }
                        "312" => { // RPL_WHOISSERVER
                            if message.params.len() >= 4 {
                                let nick = &message.params[1];
                                let server = &message.params[2];
                                let server_info = &message.params[3];
                                
                                let server_info_text = format!("{} ({})", server, server_info);
                                
                                // Update WHOIS modal if it exists
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.server_info = Some(server_info_text);
                                    }
                                }
                            }
                        }
                        "313" => { // RPL_WHOISOPERATOR
                            if message.params.len() >= 3 {
                                let nick = &message.params[1];
                                
                                // Update WHOIS modal if it exists
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.operator = true;
                                    }
                                }
                            }
                        }
                        "317" => { // RPL_WHOISIDLE
                            if message.params.len() >= 4 {
                                let nick = &message.params[1];
                                let idle_seconds: u64 = message.params[2].parse().unwrap_or(0);
                                let signon_time: u64 = message.params[3].parse().unwrap_or(0);
                                
                                let idle_time = if idle_seconds < 60 {
                                    format!("{}s", idle_seconds)
                                } else if idle_seconds < 3600 {
                                    format!("{}m {}s", idle_seconds / 60, idle_seconds % 60)
                                } else {
                                    format!("{}h {}m", idle_seconds / 3600, (idle_seconds % 3600) / 60)
                                };
                                
                                let signon_date = if signon_time > 0 {
                                    use chrono::{Utc, TimeZone};
                                    let dt = Utc.timestamp_opt(signon_time as i64, 0).single().unwrap_or_else(|| Utc::now());
                                    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                                } else {
                                    "unknown".to_string()
                                };
                                
                                let idle_info_text = format!("{} (signed on: {})", idle_time, signon_date);
                                
                                // Update WHOIS modal if it exists
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.idle_info = Some(idle_info_text);
                                    }
                                }
                            }
                        }
                        "318" => { // RPL_ENDOFWHOIS
                            if message.params.len() >= 2 {
                                let nick = &message.params[1];
                                
                                // Mark end of WHOIS and show modal if it exists
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.end_received = true;
                                        // Modal will be displayed on the next frame
                                    }
                                }
                            }
                        }
                        "319" => { // RPL_WHOISCHANNELS
                            if message.params.len() >= 3 {
                                let nick = &message.params[1];
                                let channels = &message.params[2];
                                
                                // Update WHOIS modal if it exists
                                if let Some(ref mut modal) = self.whois_modal {
                                    if modal.nick == *nick {
                                        modal.channels = Some(channels.clone());
                                    }
                                }
                            }
                        }
                        // Other WHOIS-related numerics - silently handled by modal system
                        _ => {
                            // Log unknown numerics to debug
                            iron_debug!("tui", "Unhandled numeric IRC message: {} with params: {:?}", message.command, message.params);
                        }
                    }
                } else {
                    // Non-numeric commands
                    iron_debug!("tui", "Unhandled IRC message type: {} with params: {:?}", message.command, message.params);
                }
                
                if let Err(e) = self.client.handle_message(message).await {
                    iron_error!("tui", "Error forwarding message to client: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_tagmsg(&mut self, message: IrcMessage) -> Result<()> {
        // TAGMSG is used for reactions and other tag-only messages
        if let Some(target) = message.params.get(0) {
            // Check if this is a reaction
            if let Some(react_tag) = message.get_tag("+draft/react") {
                // Get the message ID to react to (could be from +draft/reply or other tag)
                let msgid_value = message.get_tag("+draft/reply")
                    .and_then(|opt| opt.as_ref())
                    .or_else(|| message.get_tag("msgid").and_then(|opt| opt.as_ref()));
                    
                if let Some(msgid_str) = msgid_value {
                    // This is a reaction message
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");
                    
                    if let Some(reaction_value) = react_tag {
                        self.handle_reaction(target, sender, reaction_value, msgid_str).await?;
                    }
                }
            }
        }
        
        // Forward to client for protocol handling
        if let Err(e) = self.client.handle_message(message).await {
            iron_error!("tui", "Error forwarding TAGMSG to client: {}", e);
        }
        
        Ok(())
    }

    async fn handle_reaction(&mut self, channel: &str, sender: &str, reaction: &str, message_id: &str) -> Result<()> {
        // Validate input parameters
        if channel.trim().is_empty() {
            iron_error!("handle_reaction", "Invalid channel name");
            return Ok(());
        }
        
        if sender.trim().is_empty() {
            iron_error!("handle_reaction", "Invalid sender name");  
            return Ok(());
        }
        
        if reaction.trim().is_empty() {
            iron_error!("handle_reaction", "Invalid reaction");
            return Ok(());
        }
        
        if message_id.trim().is_empty() {
            iron_error!("handle_reaction", "Invalid message ID");
            return Ok(());
        }
        
        // Find the message to react to
        if let Some(channel_data) = self.channels.get_mut(channel) {
            for (index, message) in channel_data.messages.iter_mut().enumerate() {
                // Check both server-provided message ID and fallback timestamp-based ID
                let timestamp_id = format!("{}_{}", message.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), index);
                let matches_id = message.message_id.as_ref() == Some(&message_id.to_string()) || message_id == timestamp_id;
                
                if matches_id {
                    // Extract emoji from reaction (remove +/- prefix)
                    let emoji = if reaction.starts_with('+') {
                        &reaction[1..]
                    } else {
                        reaction
                    };
                    
                    // Validate emoji is not empty and reasonable length
                    if emoji.trim().is_empty() {
                        iron_error!("handle_reaction", "Empty emoji after prefix removal");
                        return Ok(());
                    }
                    
                    if emoji.len() > 50 {
                        iron_error!("handle_reaction", "Emoji too long: {} characters", emoji.len());
                        return Ok(());
                    }
                    
                    // Find or create reaction entry
                    let mut found = false;
                    for (existing_emoji, count) in &mut message.reactions {
                        if existing_emoji == emoji {
                            if reaction.starts_with('+') {
                                if *count < 999 {  // Reasonable limit to prevent spam/overflow
                                    *count += 1;
                                } else {
                                    iron_warn!("handle_reaction", "Reaction count limit reached for emoji: {}", emoji);
                                }
                            } else if reaction.starts_with('-') && *count > 0 {
                                *count -= 1;
                            }
                            found = true;
                            break;
                        }
                    }
                    
                    if !found && reaction.starts_with('+') {
                        // Limit the number of different reactions per message
                        if message.reactions.len() < 20 {  // Reasonable limit
                            message.reactions.push((emoji.to_string(), 1));
                        } else {
                            iron_warn!("handle_reaction", "Too many different reactions on message, ignoring: {}", emoji);
                        }
                    }
                    
                    // Remove reactions with 0 count
                    message.reactions.retain(|(_, count)| *count > 0);
                    
                    self.add_system_message(&format!("Reaction {} {} by {} on message in {}", 
                        emoji, 
                        if reaction.starts_with('+') { "added" } else { "removed" },
                        sender,
                        channel
                    ));
                    
                    break;
                }
            }
        } else {
            iron_warn!("handle_reaction", "Channel '{}' not found for reaction", channel);
            return Ok(());
        }
        
        // If we get here, the message wasn't found
        iron_debug!("handle_reaction", "Message with ID '{}' not found in channel '{}'", message_id, channel);
        
        Ok(())
    }

    async fn show_reactions_for_message(&mut self, message_id: &str, message_author: &str) -> Result<()> {
        // Find the message and collect detailed reaction information with users
        let mut reactions_with_users: Vec<(String, Vec<String>)> = Vec::new();
        
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                // Find the message by looking through all messages for a matching ID or timestamp-based ID
                for (index, message) in channel.messages.iter().enumerate() {
                    let timestamp_id = format!("{}_{}", message.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), index);
                    
                    if message_id == timestamp_id || message.message_id.as_ref() == Some(&message_id.to_string()) {
                        // Convert basic reactions to detailed format
                        // For now, we'll simulate users since we don't store individual users who reacted
                        for (emoji, count) in &message.reactions {
                            let users: Vec<String> = (1..=*count).map(|i| 
                                if i == 1 { message_author.to_string() }
                                else { format!("user{}", i) }
                            ).collect();
                            reactions_with_users.push((emoji.clone(), users));
                        }
                        break;
                    }
                }
            }
        }
        
        // Create the reaction modal
        self.reaction_modal = Some(ReactionModal {
            message_id: message_id.to_string(),
            message_author: message_author.to_string(),
            reactions: reactions_with_users,
        });
        
        Ok(())
    }

    // Helper methods
    fn add_user_tab(&mut self, nick: String) {
        // Add user tab if it doesn't exist
        if !self.channels.contains_key(&nick) {
            self.channels.insert(nick.clone(), ChannelData {
                name: nick.clone(),
                messages: Vec::new(),
                users: Vec::new(),  // Private messages don't have user lists
                users_expanded: false,
                topic: None,  // Private messages don't have topics
                unread_count: 0,
                activity: ActivityLevel::None,
                history_loaded: false,
                loading_history: false,
                oldest_message_id: None,
                can_load_more: true,
            });
            
            // Insert user tabs after Server but before channels
            // Find Server tab position
            let server_pos = self.channel_order.iter().position(|name| name == "Server").unwrap_or(0);
            self.channel_order.insert(server_pos + 1, nick);
        }
    }

    fn add_channel(&mut self, name: String) {
        if !self.channels.contains_key(&name) {
            self.channels.insert(name.clone(), ChannelData {
                name: name.clone(),
                messages: Vec::new(),
                users: Vec::new(),
                users_expanded: false,  // Start collapsed
                topic: None,
                unread_count: 0,
                activity: ActivityLevel::None,
                // History management
                history_loaded: false,
                loading_history: false,
                oldest_message_id: None,
                can_load_more: true,
            });
            self.channel_order.push(name.clone());
            self.channel_users_expanded.insert(name, false);
        }
    }

    fn remove_channel(&mut self, name: &str) {
        self.channels.remove(name);
        if let Some(pos) = self.channel_order.iter().position(|x| x == name) {
            self.channel_order.remove(pos);
            if self.current_tab >= pos && self.current_tab > 0 {
                self.current_tab -= 1;
            }
        }
    }

    fn switch_to_channel(&mut self, name: &str) {
        if let Some(pos) = self.channel_order.iter().position(|x| x == name) {
            self.current_tab = pos;
        }
    }

    #[allow(dead_code)]
    fn next_tab(&mut self) {
        if !self.channel_order.is_empty() {
            self.current_tab = (self.current_tab + 1) % self.channel_order.len();
            self.mark_current_as_read();
            self.message_scroll = 0; // Reset scroll when switching tabs
        }
    }

    #[allow(dead_code)]
    fn prev_tab(&mut self) {
        if !self.channel_order.is_empty() {
            self.current_tab = if self.current_tab > 0 {
                self.current_tab - 1
            } else {
                self.channel_order.len() - 1
            };
            self.mark_current_as_read();
            self.message_scroll = 0; // Reset scroll when switching tabs
        }
    }

    fn mark_current_as_read(&mut self) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get_mut(&channel_name) {
                channel.unread_count = 0;
                channel.activity = ActivityLevel::None;
            }
        }
    }

    fn get_current_channel_name(&self) -> Option<String> {
        self.channel_order.get(self.current_tab).cloned()
    }

    fn get_total_sidebar_items(&self) -> usize {
        // Start with channels header + channel count
        let mut total = 1 + self.channel_order.len(); // 1 for "Channels" header
        
        // Add spacing after channels
        total += 1;
        
        // Add users section if current channel has users
        if let Some(chan_name) = self.channel_order.get(self.current_tab) {
            if let Some(channel) = self.channels.get(chan_name) {
                if !channel.users.is_empty() {
                    total += 1; // Users header
                    if channel.users_expanded {
                        total += channel.users.len(); // Individual users
                    }
                }
            }
        }
        
        total
    }

    fn get_sidebar_item_type(&self, index: usize) -> SidebarItemType {
        if index == 0 {
            return SidebarItemType::ChannelsHeader;
        }
        
        // Check if it's a channel
        if index > 0 && index <= self.channel_order.len() {
            return SidebarItemType::Channel(index - 1);
        }
        
        let after_channels = self.channel_order.len() + 1; // +1 for header
        
        // Check if it's the spacing after channels
        if index == after_channels {
            return SidebarItemType::Spacing;
        }
        
        // Check if it's users section
        if let Some(chan_name) = self.channel_order.get(self.current_tab) {
            if let Some(channel) = self.channels.get(chan_name) {
                if !channel.users.is_empty() {
                    let users_header_index = after_channels + 1;
                    if index == users_header_index {
                        return SidebarItemType::UsersHeader;
                    }
                    
                    if channel.users_expanded && index > users_header_index {
                        let user_index = index - users_header_index - 1;
                        if user_index < channel.users.len() {
                            return SidebarItemType::User(user_index);
                        }
                    }
                }
            }
        }
        
        SidebarItemType::Spacing
    }

    async fn handle_input_keys(&mut self, key_code: KeyCode) -> Result<()> {
        match key_code {
            KeyCode::Enter => {
                // If we're in the input, send the message
                if !self.input.is_empty() {
                    self.handle_input().await?;
                }
            }
            KeyCode::Backspace => {
                self.tab_completion_state = None;
                if !self.input.is_empty() && self.input_cursor > 0 {
                    self.input.remove(self.input_cursor - 1);
                    self.input_cursor -= 1;
                }
            }
            KeyCode::Delete => {
                self.tab_completion_state = None;
                if self.input_cursor < self.input.len() {
                    self.input.remove(self.input_cursor);
                }
            }
            KeyCode::Left => {
                self.tab_completion_state = None;
                if self.input_cursor > 0 {
                    self.input_cursor -= 1;
                }
            }
            KeyCode::Right => {
                self.tab_completion_state = None;
                if self.input_cursor < self.input.len() {
                    self.input_cursor += 1;
                }
            }
            KeyCode::Home => {
                self.tab_completion_state = None;
                self.input_cursor = 0;
            }
            KeyCode::End => {
                self.tab_completion_state = None;
                self.input_cursor = self.input.len();
            }
            KeyCode::Char(c) => {
                self.tab_completion_state = None; // Clear completion on new input
                self.input.insert(self.input_cursor, c);
                self.input_cursor += 1;
            }
            _ => {}
        }
        Ok(())
    }

    fn sidebar_up(&mut self) {
        if self.sidebar_selection > 0 {
            self.sidebar_selection -= 1;
            // Skip spacing if we land on it
            while self.is_spacing_item(self.sidebar_selection) && self.sidebar_selection > 0 {
                self.sidebar_selection -= 1;
            }
        }
        // No send button logic needed
    }

    fn sidebar_down(&mut self) {
        let max_items = self.get_total_sidebar_items();
        if self.sidebar_selection < max_items - 1 {
            self.sidebar_selection += 1;
            // Skip spacing if we land on it
            while self.is_spacing_item(self.sidebar_selection) && self.sidebar_selection < max_items - 1 {
                self.sidebar_selection += 1;
            }
        }
        // No send button, so stay at bottom item
    }


    fn is_spacing_item(&self, index: usize) -> bool {
        matches!(self.get_sidebar_item_type(index), SidebarItemType::Spacing)
    }

    fn sidebar_select(&mut self) {        
        match self.get_sidebar_item_type(self.sidebar_selection) {
            SidebarItemType::Channel(channel_index) => {
                // Switch to the selected channel
                if channel_index != self.current_tab {
                    self.current_tab = channel_index;
                    self.message_scroll = 0;
                    self.mark_current_as_read();
                }
            }
            SidebarItemType::UsersHeader => {
                // Toggle users expansion for current channel
                if let Some(chan_name) = self.get_current_channel_name() {
                    if let Some(channel) = self.channels.get_mut(&chan_name) {
                        if !channel.users.is_empty() {
                            channel.users_expanded = !channel.users_expanded;
                        }
                    }
                }
            }
            SidebarItemType::User(user_index) => {
                // Show context menu for user
                self.show_user_context_menu(user_index);
            }
            SidebarItemType::ChannelsHeader | SidebarItemType::Spacing => {
                // Do nothing for headers and spacing
            }
        }
    }


    fn show_user_context_menu(&mut self, user_index: usize) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                if let Some(username) = channel.users.get(user_index) {
                    // Determine available actions based on user and our permissions
                    let mut options = vec![
                        UserAction::Query,
                        UserAction::Whois,
                    ];
                    
                    // Add moderator actions if the user isn't ourselves
                    let clean_username = username.trim_start_matches(['@', '+', '%', '&', '~']);
                    if clean_username != self.client.current_nickname() {
                        options.push(UserAction::Kick);
                        options.push(UserAction::Ban);
                        
                        // Add op/deop based on current status
                        if username.starts_with('@') {
                            options.push(UserAction::Deop);
                        } else {
                            options.push(UserAction::Op);
                        }
                    }
                    
                    options.push(UserAction::Cancel);
                    
                    self.user_context_menu = Some(UserContextMenu {
                        username: clean_username.to_string(),
                        channel: channel_name,
                        selected_option: 0,
                        options,
                    });
                }
            }
        }
    }

    async fn handle_emoji_picker_key(&mut self, key_code: KeyCode) -> Result<()> {
        iron_debug!("emoji_picker", "Handling emoji picker key: {:?}", key_code);
        
        if let Some(ref mut picker) = self.emoji_picker {
            match key_code {
                KeyCode::Esc => {
                    self.emoji_picker = None;
                }
                KeyCode::Up => {
                    if picker.selected_index > 0 {
                        picker.selected_index -= 1;
                    }
                }
                KeyCode::Down => {
                    if picker.selected_index < picker.filtered_emojis.len().saturating_sub(1) {
                        picker.selected_index += 1;
                    }
                }
                KeyCode::Enter => {
                    iron_debug!("emoji_picker", "Enter pressed, selected_index: {}", picker.selected_index);
                    
                    if let Some(&(emoji, _)) = picker.filtered_emojis.get(picker.selected_index) {
                        iron_debug!("emoji_picker", "Selected emoji: {}, message_id: {}, channel: {}", emoji, picker.message_id, picker.channel);
                        
                        // Additional validation before sending
                        if !self.client.is_capability_enabled("+draft/react") {
                            iron_error!("emoji_picker", "Server no longer supports reactions");
                            self.add_system_message("❌ Server does not support reactions");
                            self.emoji_picker = None;
                            return Ok(());
                        }
                        
                        if picker.message_id.trim().is_empty() {
                            iron_error!("emoji_picker", "Invalid message ID");
                            self.add_system_message("❌ Cannot react - invalid message");
                            self.emoji_picker = None;
                            return Ok(());
                        }
                        
                        if picker.channel.trim().is_empty() {
                            iron_error!("emoji_picker", "Invalid channel");
                            self.add_system_message("❌ Cannot react - invalid channel");
                            self.emoji_picker = None;
                            return Ok(());
                        }
                        
                        // Send the reaction using iron-protocol
                        use legion_protocol::{MessageReaction, ReactionAction};
                        
                        iron_debug!("emoji_picker", "Creating MessageReaction...");
                        let reaction = MessageReaction::new(
                            picker.channel.clone(),
                            picker.message_id.clone(),
                            emoji.to_string(),
                            ReactionAction::Add
                        );
                        
                        iron_debug!("emoji_picker", "Converting reaction to IRC message...");
                        let reaction_msg = reaction.to_message();
                        
                        iron_debug!("emoji_picker", "Sending reaction message: {}", reaction_msg);
                        match self.client.send_message(&reaction_msg).await {
                            Ok(_) => {
                                iron_debug!("emoji_picker", "Reaction sent successfully");
                                self.add_system_message(&format!("✅ Reacted {} to message", emoji));
                            }
                            Err(e) => {
                                iron_error!("emoji_picker", "Failed to send reaction: {}", e);
                                self.add_system_message(&format!("❌ Failed to send reaction: {}", e));
                            }
                        }
                        
                        self.emoji_picker = None;
                        iron_debug!("emoji_picker", "Emoji picker closed");
                    } else {
                        iron_warn!("emoji_picker", "No emoji selected at index {} (total: {})", picker.selected_index, picker.filtered_emojis.len());
                        self.add_system_message("❌ No emoji selected");
                    }
                }
                KeyCode::Backspace => {
                    if !picker.search_query.is_empty() {
                        picker.search_query.pop();
                        picker.update_filter();
                    }
                }
                KeyCode::Char(c) => {
                    picker.search_query.push(c);
                    picker.update_filter();
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_context_menu_key(&mut self, key_code: KeyCode) -> Result<()> {
        // Handle user context menu
        if let Some(ref mut menu) = self.user_context_menu {
            match key_code {
                KeyCode::Up => {
                    if menu.selected_option > 0 {
                        menu.selected_option -= 1;
                    }
                }
                KeyCode::Down => {
                    if menu.selected_option < menu.options.len() - 1 {
                        menu.selected_option += 1;
                    }
                }
                KeyCode::Enter => {
                    let action = menu.options[menu.selected_option].clone();
                    let username = menu.username.clone();
                    let channel = menu.channel.clone();
                    self.user_context_menu = None; // Close menu
                    
                    // Execute the selected action
                    self.execute_user_action(action, &username, &channel).await?;
                }
                KeyCode::Esc => {
                    self.user_context_menu = None; // Close menu
                }
                _ => {}
            }
        }
        // Handle message context menu
        else if let Some(ref mut menu) = self.message_context_menu {
            match key_code {
                KeyCode::Up => {
                    if menu.selected_option > 0 {
                        menu.selected_option -= 1;
                    }
                }
                KeyCode::Down => {
                    if menu.selected_option < menu.options.len() - 1 {
                        menu.selected_option += 1;
                    }
                }
                KeyCode::Enter => {
                    let action = menu.options[menu.selected_option].clone();
                    let message_id = menu.message_id.clone();
                    let message_author = menu.message_author.clone();
                    
                    iron_debug!("context_menu", "Executing message action: {:?} for message_id: {}, author: {}", action, message_id, message_author);
                    
                    self.message_context_menu = None; // Close menu
                    
                    // Execute the selected action
                    self.execute_message_action(action, &message_id, &message_author).await?;
                }
                KeyCode::Esc => {
                    self.message_context_menu = None; // Close menu
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn execute_user_action(&mut self, action: UserAction, username: &str, channel: &str) -> Result<()> {
        match action {
            UserAction::Query => {
                // Switch to or create a private message tab
                self.add_system_message(&format!("Starting private message with {}", username));
                // TODO: Create actual PM tab
            }
            UserAction::Whois => {
                // Send WHOIS command
                let whois_msg = format!("WHOIS {}", username);
                self.client.send_raw(&whois_msg).await?;
                self.add_system_message(&format!("Requesting WHOIS for {}", username));
            }
            UserAction::Kick => {
                // Send KICK command
                let kick_msg = format!("KICK {} {}", channel, username);
                self.client.send_raw(&kick_msg).await?;
                self.add_system_message(&format!("Attempting to kick {}", username));
            }
            UserAction::Ban => {
                // Send MODE +b command
                let ban_msg = format!("MODE {} +b {}!*@*", channel, username);
                self.client.send_raw(&ban_msg).await?;
                self.add_system_message(&format!("Attempting to ban {}", username));
            }
            UserAction::Op => {
                // Send MODE +o command
                let op_msg = format!("MODE {} +o {}", channel, username);
                self.client.send_raw(&op_msg).await?;
                self.add_system_message(&format!("Attempting to give op to {}", username));
            }
            UserAction::Deop => {
                // Send MODE -o command
                let deop_msg = format!("MODE {} -o {}", channel, username);
                self.client.send_raw(&deop_msg).await?;
                self.add_system_message(&format!("Attempting to remove op from {}", username));
            }
            UserAction::Cancel => {
                // Do nothing, menu already closed
            }
        }
        Ok(())
    }

    async fn handle_reaction_modal_key(&mut self, key_code: KeyCode) -> Result<()> {
        // Any key closes the reaction modal as requested by user
        match key_code {
            _ => {
                self.reaction_modal = None;
            }
        }
        Ok(())
    }

    async fn handle_whois_modal_key(&mut self, key_code: KeyCode) -> Result<()> {
        // Any key closes the WHOIS modal
        match key_code {
            _ => {
                self.whois_modal = None;
            }
        }
        Ok(())
    }

    async fn execute_message_action(&mut self, action: MessageAction, message_id: &str, message_author: &str) -> Result<()> {
        match action {
            MessageAction::Reply => {
                if let Some(_channel_name) = self.get_current_channel_name().clone() {
                    iron_debug!("reply", "Starting reply action for message_id: {}, author: {}", message_id, message_author);
                    
                    // Store the message ID we're replying to
                    self.reply_to_message_id = Some(message_id.to_string());
                    
                    // Prompt for reply text
                    self.add_system_message(&format!("Type your reply to {} in the input field below", message_author));
                    
                    // Set up reply mode in input with @ mention
                    self.input = format!("@{} ", message_author);
                    self.input_cursor = self.input.len();
                    
                    iron_debug!("reply", "Reply mode activated, replying to message: {}", message_id);
                }
            }
            MessageAction::React => {
                iron_debug!("reaction", "Starting reaction action for message_id: {}, author: {}", message_id, message_author);
                
                // Validate reaction is possible
                if !self.client.is_capability_enabled("+draft/react") {
                    iron_error!("reaction", "Server does not support reactions (+draft/react)");
                    self.add_system_message("❌ Server does not support reactions");
                    return Ok(());
                }
                
                if message_id.trim().is_empty() {
                    iron_error!("reaction", "Cannot react to message without ID");
                    self.add_system_message("❌ Cannot react to this message (no message ID)");
                    return Ok(());
                }
                
                if let Some(channel_name) = self.get_current_channel_name().clone() {
                    iron_debug!("reaction", "Creating emoji picker for channel: {}", channel_name);
                    
                    // Show emoji picker
                    self.emoji_picker = Some(EmojiPicker::new(
                        message_id.to_string(),
                        channel_name
                    ));
                    
                    iron_debug!("reaction", "Emoji picker created successfully");
                } else {
                    iron_error!("reaction", "No current channel found when trying to react to message");
                    self.add_system_message("❌ Cannot react - not in a channel");
                }
            }
            MessageAction::ViewReactions => {
                if message_id.trim().is_empty() {
                    iron_error!("reaction", "Cannot view reactions for message without ID");
                    self.add_system_message("❌ Cannot view reactions for this message");
                    return Ok(());
                }
                
                // Show detailed reactions for this message
                self.show_reactions_for_message(message_id, message_author).await?;
            }
            MessageAction::Quote => {
                // Add quoted text to input
                if let Some(ref menu) = self.message_context_menu {
                    self.input = format!("> {} said: {}\n", menu.message_author, menu.message_content);
                    self.input_cursor = self.input.len();
                    self.add_system_message("Message quoted - type your response");
                }
            }
            MessageAction::Copy => {
                // Copy message to clipboard (system dependent)
                self.add_system_message(&format!("Message from {} copied to system clipboard", message_author));
                // TODO: Implement actual clipboard functionality
            }
            MessageAction::Cancel => {
                // Do nothing, menu already closed
            }
        }
        Ok(())
    }

    fn select_previous_message(&mut self) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                let total_messages = channel.messages.len();
                if total_messages > 0 {
                    match self.selected_message_index {
                        None => {
                            // Select the most recent message (index 0 from bottom)
                            self.selected_message_index = Some(0);
                        }
                        Some(current_index) => {
                            // Move to previous message (higher index, older message)
                            let max_index = total_messages.saturating_sub(1);
                            if current_index < max_index {
                                self.selected_message_index = Some(current_index + 1);
                                
                                // Auto-scroll if needed to keep message visible
                                self.ensure_message_visible(current_index + 1);
                            } else {
                                // At the oldest visible message, try to scroll up and load more history
                                self.auto_scroll_for_navigation(true);
                            }
                        }
                    }
                }
            }
        }
    }

    fn select_next_message(&mut self) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                let total_messages = channel.messages.len();
                if total_messages > 0 {
                    match self.selected_message_index {
                        None => {
                            // Select the most recent message (index 0 from bottom)
                            self.selected_message_index = Some(0);
                        }
                        Some(current_index) => {
                            // Move to next message (lower index, newer message)
                            if current_index > 0 {
                                self.selected_message_index = Some(current_index - 1);
                                
                                // Auto-scroll if needed to keep message visible
                                self.ensure_message_visible(current_index - 1);
                            } else {
                                // At the newest message, scroll down to show more recent content
                                self.auto_scroll_for_navigation(false);
                            }
                        }
                    }
                }
            }
        }
    }

    fn show_message_context_menu(&mut self) {
        if let Some(selected_index) = self.selected_message_index {
            if let Some(channel_name) = self.get_current_channel_name() {
                if let Some(channel) = self.channels.get(&channel_name) {
                    if let Some(message) = channel.messages.get(selected_index) {
                        // Build options based on server capabilities
                        let mut options = vec![];
                        
                        // Only add Reply if:
                        // 1. Server supports +draft/reply capability
                        // 2. Message is a user message (Privmsg or Notice)
                        // 3. Message has a valid message ID
                        // 4. Message is not from ourselves
                        if self.client.is_capability_enabled("+draft/reply")
                            && matches!(message.message_type, MessageType::Privmsg | MessageType::Notice)
                            && message.message_id.is_some() 
                            && message.sender.as_ref().map_or(true, |sender| sender != self.client.current_nickname()) {
                            options.push(MessageAction::Reply);
                        }
                        
                        // Only add React if:
                        // 1. Server supports +draft/react capability
                        // 2. Message is a user message (Privmsg or Notice) 
                        // 3. Message has a valid message ID
                        // 4. Message is not from ourselves
                        if self.client.is_capability_enabled("+draft/react") 
                            && matches!(message.message_type, MessageType::Privmsg | MessageType::Notice)
                            && message.message_id.is_some()
                            && message.sender.as_ref().map_or(true, |sender| sender != self.client.current_nickname()) {
                            options.push(MessageAction::React);
                        }
                        
                        options.extend_from_slice(&[
                            MessageAction::ViewReactions,
                            MessageAction::Quote,
                            MessageAction::Copy,
                            MessageAction::Cancel,
                        ]);
                        
                        self.message_context_menu = Some(MessageContextMenu {
                            message_id: message.message_id.clone().unwrap_or_else(|| 
                                format!("{}_{}", message.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), selected_index)
                            ),
                            message_author: message.sender.clone().unwrap_or_else(|| 
                                match message.message_type {
                                    MessageType::System => "System".to_string(),
                                    MessageType::Join => "Server".to_string(),
                                    MessageType::Part => "Server".to_string(),
                                    MessageType::Topic => "Server".to_string(),
                                    _ => "Unknown".to_string(),
                                }
                            ),
                            message_content: message.content.clone(),
                            selected_option: 0,
                            options,
                        });
                    }
                }
            }
        }
    }

    fn clear_message_selection(&mut self) {
        self.selected_message_index = None;
        self.message_context_menu = None;
    }

    /// Ensure the selected message is visible in the current scroll view
    fn ensure_message_visible(&mut self, message_index: usize) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                let total_messages = channel.messages.len();
                if total_messages == 0 { return; }
                
                // Calculate viewport (messages currently visible)
                let messages_per_page = 20; // Approximate based on terminal height
                let scroll_offset = self.message_scroll;
                
                // Message indices are from newest (0) to oldest (total-1)
                // Scroll offset 0 = showing newest messages
                let viewport_start = scroll_offset;
                let viewport_end = scroll_offset + messages_per_page;
                
                // If selected message is outside viewport, adjust scroll
                if message_index < viewport_start {
                    // Message is too new (below current view), scroll down
                    self.message_scroll = message_index;
                } else if message_index >= viewport_end {
                    // Message is too old (above current view), scroll up
                    self.message_scroll = message_index.saturating_sub(messages_per_page / 2);
                }
            }
        }
    }

    /// Handle auto-scrolling when navigating beyond current view
    fn auto_scroll_for_navigation(&mut self, going_up: bool) {
        if going_up {
            // Going to older messages - scroll up by a few messages
            let scroll_amount = 5;
            if let Some(channel_name) = self.get_current_channel_name() {
                if let Some(channel) = self.channels.get(&channel_name) {
                    let max_scroll = channel.messages.len().saturating_sub(1);
                    self.message_scroll = (self.message_scroll + scroll_amount).min(max_scroll);
                    
                    // Try to select a message in the new view
                    let new_selection = (self.selected_message_index.unwrap_or(0) + scroll_amount).min(max_scroll);
                    self.selected_message_index = Some(new_selection);
                }
            }
        } else {
            // Going to newer messages - scroll down
            let scroll_amount = 5;
            self.message_scroll = self.message_scroll.saturating_sub(scroll_amount);
            
            // Try to select a message in the new view
            if let Some(current_selection) = self.selected_message_index {
                let new_selection = current_selection.saturating_sub(scroll_amount);
                self.selected_message_index = Some(new_selection);
            } else {
                // No selection, clear it to go back to input
                self.selected_message_index = None;
            }
        }
    }

    /// Scroll up through message history (PageUp)
    async fn scroll_up(&mut self) -> Result<()> {
        let current_channel = self.get_current_channel_name();
        if current_channel.is_none() {
            return Ok(());
        }
        
        let channel_name = current_channel.unwrap();
        let message_count = self.channels.get(&channel_name)
            .map(|c| c.messages.len())
            .unwrap_or(0);
        
        if message_count == 0 {
            return Ok(());
        }
        
        // Scroll up by one screen (roughly 10 messages)
        let scroll_amount = 10;
        let max_scroll = message_count;
        self.message_scroll = (self.message_scroll + scroll_amount).min(max_scroll);
        
        // Check if we're close to the top and need to load more history
        let remaining_above = max_scroll.saturating_sub(self.message_scroll);
        if remaining_above <= 5 {
            // We're close to the top, try to load more history
            self.try_load_more_history(&channel_name).await?;
        }
        
        Ok(())
    }

    /// Scroll down through message history (PageDown)
    fn scroll_down(&mut self) {
        let scroll_amount = 10;
        self.message_scroll = if self.message_scroll >= scroll_amount {
            self.message_scroll - scroll_amount
        } else {
            0 // At bottom
        };
    }

    /// Go to top of message history (Home)
    async fn scroll_to_top(&mut self) -> Result<()> {
        let current_channel = self.get_current_channel_name();
        if current_channel.is_none() {
            return Ok(());
        }
        
        let channel_name = current_channel.unwrap();
        let message_count = self.channels.get(&channel_name)
            .map(|c| c.messages.len())
            .unwrap_or(0);
        
        self.message_scroll = message_count;
        
        // Always try to load more history when going to top
        self.try_load_more_history(&channel_name).await?;
        
        Ok(())
    }

    /// Go to bottom of message history (End)
    fn scroll_to_bottom(&mut self) {
        self.message_scroll = 0;
    }

    /// Try to load more history for a channel
    async fn try_load_more_history(&mut self, channel_name: &str) -> Result<()> {
        if let Some(channel_data) = self.channels.get(channel_name) {
            if channel_data.can_load_more && !channel_data.loading_history {
                // Load more messages before the oldest one
                self.load_more_history(channel_name, 50).await?;
            }
        }
        Ok(())
    }

    fn handle_tab_completion(&mut self) {
        // If we have existing completion state, cycle through it
        if let Some(ref mut state) = self.tab_completion_state {
            state.current_index = (state.current_index + 1) % state.completions.len();
            let completion = &state.completions[state.current_index];
            
            // Replace the current completion with the next one
            self.input = format!("{}{}{}", 
                &state.original_input[..state.completion_start],
                completion,
                &state.original_input[state.original_cursor..]
            );
            self.input_cursor = state.completion_start + completion.len();
        } else {
            // Start new tab completion
            self.start_tab_completion();
        }
    }

    fn start_tab_completion(&mut self) {
        let input = self.input.clone(); // Clone to avoid borrow checker issues
        let cursor = self.input_cursor;
        
        // Find the word to complete (go backwards from cursor to find word boundary)
        let mut word_start = cursor;
        while word_start > 0 {
            let ch = input.chars().nth(word_start - 1).unwrap_or(' ');
            if ch.is_whitespace() || ch == '/' {
                break;
            }
            word_start -= 1;
        }
        
        let word_to_complete = &input[word_start..cursor];
        if word_to_complete.is_empty() {
            return;
        }
        
        let mut completions = Vec::new();
        
        // Get current channel users for nickname completion
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                for user in &channel.users {
                    if user.to_lowercase().starts_with(&word_to_complete.to_lowercase()) {
                        // Add colon suffix if completing at start of message
                        let completion = if word_start == 0 {
                            format!("{}: ", user)
                        } else {
                            user.clone()
                        };
                        completions.push(completion);
                    }
                }
            }
        }
        
        // Add command completions if starting with /
        if word_to_complete.starts_with('/') {
            let commands = [
                "/join", "/part", "/quit", "/nick", "/msg", "/raw", "/help", "/history",
                "/ns", "/cs", "/ms", "/os", "/hs", "/bs"
            ];
            
            for cmd in &commands {
                if cmd.to_lowercase().starts_with(&word_to_complete.to_lowercase()) {
                    completions.push(format!("{} ", cmd));
                }
            }
        }
        
        if !completions.is_empty() {
            completions.sort();
            completions.dedup();
            
            let completion = &completions[0];
            
            // Replace the word with the first completion
            let new_input = format!("{}{}{}", 
                &input[..word_start],
                completion,
                &input[cursor..]
            );
            
            self.input = new_input;
            self.input_cursor = word_start + completion.len();
            
            // Save completion state
            self.tab_completion_state = Some(TabCompletionState {
                original_input: input.to_string(),
                original_cursor: cursor,
                completions,
                current_index: 0,
                completion_start: word_start,
            });
        }
    }

    fn add_system_message(&mut self, content: &str) {
        self.add_message("Server", None, content.to_string(), MessageType::System);
    }

    fn add_log_message(&mut self, content: &str) {
        self.add_message("Server", None, content.to_string(), MessageType::System);
        
        // Also log to file
        self.log_to_file(content);
    }

    fn setup_file_logging(&mut self) {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let log_path = format!("{}/.legionnaire.log", home_dir);
        
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path) {
            Ok(file) => {
                self.log_file = Some(file);
                self.add_log_message(&format!("Logging to {}", log_path));
            }
            Err(e) => {
                self.add_log_message(&format!("Failed to open log file {}: {}", log_path, e));
            }
        }
    }

    /// Strip IRC color codes and formatting from text
    fn strip_irc_formatting(text: &str) -> String {
        // IRC color codes: ^C<fg>[,<bg>] where ^C is ASCII 3 (0x03)
        // Bold: ^B (ASCII 2, 0x02)
        // Italic: ^I (ASCII 29, 0x1D)  
        // Underline: ^U (ASCII 31, 0x1F)
        // Reverse: ^R (ASCII 22, 0x16)
        // Reset: ^O (ASCII 15, 0x0F)
        
        let mut result = text.to_string();
        
        // Remove color codes (most complex pattern)
        // Matches: \x03(\d{1,2}(,\d{1,2})?)?
        let color_regex = Regex::new(r"\x03(\d{1,2}(,\d{1,2})?)?").unwrap();
        result = color_regex.replace_all(&result, "").to_string();
        
        // Remove other formatting codes
        result = result.replace('\x02', ""); // Bold
        result = result.replace('\x1D', ""); // Italic
        result = result.replace('\x1F', ""); // Underline
        result = result.replace('\x16', ""); // Reverse
        result = result.replace('\x0F', ""); // Reset
        
        result
    }

    fn log_to_file(&mut self, message: &str) {
        if let Some(ref mut file) = self.log_file {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            let log_line = format!("[{}] {}\n", timestamp, message);
            let _ = file.write_all(log_line.as_bytes());
            let _ = file.flush();
        }
    }

    fn add_message(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType) {
        self.add_message_with_activity(channel, sender, content, msg_type, ActivityLevel::Message);
    }

    fn add_message_with_activity(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel) {
        self.add_message_with_timestamp(channel, sender, content, msg_type, activity, SystemTime::now());
    }

    // Helper method to add a message with reactions for testing
    #[allow(dead_code)]
    fn add_message_with_reactions(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel, reactions: Vec<(String, usize)>) {
        let message = DisplayMessage {
            timestamp: SystemTime::now(),
            sender,
            content: Self::strip_irc_formatting(&content),
            message_type: msg_type,
            message_id: Some(format!("msg-{}", rand::random::<u32>())), // Generate test ID
            reactions,
        };

        // Get current channel name first to avoid borrow conflicts
        let current_channel_name = self.get_current_channel_name();
        let is_current_channel = Some(channel) == current_channel_name.as_deref();

        if let Some(channel_data) = self.channels.get_mut(channel) {
            channel_data.messages.push(message);
            
            // Update activity only if not currently viewing this channel
            if !is_current_channel {
                channel_data.unread_count += 1;
                if activity > channel_data.activity {
                    channel_data.activity = activity;
                }
            } else {
                // If viewing this channel and at bottom, stay at bottom
                if self.message_scroll == 0 {
                    self.message_scroll = 0;
                }
            }
            
            // Keep message history reasonable
            if channel_data.messages.len() > 1000 {
                channel_data.messages.remove(0);
            }
        }
    }

    fn add_message_with_timestamp(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel, timestamp: SystemTime) {
        self.add_message_with_id(channel, sender, content, msg_type, activity, timestamp, None);
    }

    /// Load recent history for a channel automatically
    async fn load_channel_history(&mut self, channel: &str, limit: usize) -> Result<()> {
        if !self.client.has_capability("chathistory") {
            iron_debug!("tui", "Server doesn't support CHATHISTORY, skipping history load for {}", channel);
            return Ok(());
        }

        if let Some(channel_data) = self.channels.get_mut(channel) {
            if channel_data.history_loaded || channel_data.loading_history {
                return Ok(()); // Already loaded or loading
            }
            channel_data.loading_history = true;
        }

        iron_debug!("tui", "🕐 Loading recent history for channel {} (limit: {})", channel, limit);
        
        match self.client.request_recent_history(channel, limit).await {
            Ok(()) => {
                iron_debug!("tui", "✅ History request sent for {}", channel);
                Ok(())
            }
            Err(e) => {
                if let Some(channel_data) = self.channels.get_mut(channel) {
                    channel_data.loading_history = false;
                }
                iron_error!("tui", "❌ Failed to request history for {}: {}", channel, e);
                Err(e)
            }
        }
    }

    /// Load more history before the oldest message
    async fn load_more_history(&mut self, channel: &str, limit: usize) -> Result<()> {
        if !self.client.has_capability("chathistory") {
            return Ok(());
        }

        let (oldest_id, can_load_more, loading) = {
            let channel_data = self.channels.get(channel).ok_or_else(|| {
                crate::error::IronError::Connection(format!("Channel {} not found", channel))
            })?;

            (
                channel_data.oldest_message_id.clone(),
                channel_data.can_load_more,
                channel_data.loading_history,
            )
        };

        if !can_load_more || loading {
            return Ok(()); // No more history available or already loading
        }

        // Set loading state
        if let Some(channel_data) = self.channels.get_mut(channel) {
            channel_data.loading_history = true;
        }

        iron_debug!("tui", "🕐 Loading more history for {} before oldest message", channel);

        let selector = oldest_id
            .map(|id| format!("msgid={}", id))
            .unwrap_or_else(|| "*".to_string());

        match self.client.request_history_before(channel, &selector, limit).await {
            Ok(()) => {
                iron_debug!("tui", "✅ More history request sent for {}", channel);
                Ok(())
            }
            Err(e) => {
                if let Some(channel_data) = self.channels.get_mut(channel) {
                    channel_data.loading_history = false;
                }
                iron_error!("tui", "❌ Failed to request more history for {}: {}", channel, e);
                Err(e)
            }
        }
    }

    /// Handle incoming BATCH start/end for CHATHISTORY
    fn handle_history_batch(&mut self, batch_type: &str, reference: &str, is_start: bool) {
        if is_start {
            if batch_type == "chathistory" {
                iron_debug!("tui", "📦 CHATHISTORY batch start: {}", reference);
                self.current_batch = Some(reference.to_string());
                self.current_batch_type = Some(batch_type.to_string());
                // Target will be extracted from the first message in the batch
            }
        } else {
            if self.current_batch.as_deref() == Some(reference.trim_start_matches('-')) {
                iron_debug!("tui", "📦 CHATHISTORY batch end: {}", reference);
                
                // Complete history loading for the target if it's a chathistory batch
                if let Some(target) = self.current_batch_target.clone() {
                    self.complete_history_loading(&target);
                }
                
                self.current_batch = None;
                self.current_batch_type = None;
                self.current_batch_target = None;
            }
        }
    }

    /// Add a historical message (from CHATHISTORY response)
    fn add_historical_message(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, timestamp: SystemTime, message_id: Option<String>) {
        let message = DisplayMessage {
            timestamp,
            sender,
            content: Self::strip_irc_formatting(&content),
            message_type: msg_type,
            message_id: message_id.clone(),
            reactions: Vec::new(),
        };

        if let Some(channel_data) = self.channels.get_mut(channel) {
            // Insert historical messages at the beginning to maintain chronological order
            // Since CHATHISTORY LATEST returns messages in reverse chronological order,
            // we need to insert them at the front
            channel_data.messages.insert(0, message);

            // Update oldest message ID for pagination
            if let Some(msg_id) = message_id {
                channel_data.oldest_message_id = Some(msg_id);
            }

            // Mark history as loaded
            channel_data.history_loaded = true;
            channel_data.loading_history = false;
        }
    }

    /// Complete history loading for a channel
    fn complete_history_loading(&mut self, channel: &str) {
        if let Some(channel_data) = self.channels.get_mut(channel) {
            channel_data.loading_history = false;
            channel_data.history_loaded = true;
            iron_debug!("tui", "✅ History loading completed for {}", channel);
        }
    }

    fn add_message_with_id(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel, timestamp: SystemTime, message_id: Option<String>) {
        let message = DisplayMessage {
            timestamp,
            sender,
            content: Self::strip_irc_formatting(&content),
            message_type: msg_type,
            message_id,
            reactions: Vec::new(),
        };

        // Get current channel name first to avoid borrow conflicts
        let current_channel_name = self.get_current_channel_name();
        let is_current_channel = Some(channel) == current_channel_name.as_deref();

        if let Some(channel_data) = self.channels.get_mut(channel) {
            channel_data.messages.push(message);
            
            // Update activity only if not currently viewing this channel
            if !is_current_channel {
                channel_data.unread_count += 1;
                if activity > channel_data.activity {
                    channel_data.activity = activity;
                }
            } else {
                // If viewing this channel and at bottom, stay at bottom
                if self.message_scroll == 0 {
                    self.message_scroll = 0;
                }
            }
            
            // Keep message history reasonable
            if channel_data.messages.len() > 1000 {
                channel_data.messages.drain(0..100);
            }
        }
    }
    
    /// Check if auto-history loading is enabled for a specific channel
    fn should_auto_load_history(&self, channel_name: &str) -> bool {
        // Get the current server name from client config
        let server_name = &self.client.get_config().server;
        
        // Find the server configuration that matches
        for server_config in &self.config.servers {
            if server_config.host == *server_name || server_config.name == *server_name {
                return server_config.should_auto_load_history(channel_name);
            }
        }
        
        // Default to enabled if server not found in config
        iron_warn!("tui", "Server config not found for {}, defaulting to auto-load history", server_name);
        true
    }
}

impl Drop for IrcTui {
    fn drop(&mut self) {
        // Force cleanup on drop, ignoring errors
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            // DisableMouseCapture - not used since we don't enable it
        );
        let _ = self.terminal.show_cursor();
        
        // Also call our cleanup method for any additional cleanup
        let _ = self.cleanup();
    }
}