use crate::client::IronClient;
use crate::message::IrcMessage;
use crate::error::Result;
use crate::config::{Config, KeybindingsConfig};

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
use crate::{iron_debug, iron_info, iron_error};

pub struct IrcTui {
    client: IronClient,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    
    // Channel state
    channels: HashMap<String, ChannelData>,
    channel_order: Vec<String>,
    current_tab: usize,
    message_scroll: usize,
    
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
    pending_send: bool,  // Flag to indicate message should be sent
    user_context_menu: Option<UserContextMenu>,  // Active user context menu
    
    // Config
    keybindings: KeybindingsConfig,
    
    // Logging
    log_file: Option<std::fs::File>,
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
}

#[derive(Debug, Clone)]
struct DisplayMessage {
    timestamp: SystemTime,
    sender: Option<String>,
    content: String,
    message_type: MessageType,
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
            pending_send: false,
            user_context_menu: None,
            keybindings: config.keybindings.clone(),
            log_file: None,
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
            pending_send: false,
            user_context_menu: None,
            keybindings: config.keybindings.clone(),
            log_file: None,
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
                
                // Handle pending send from sidebar
                if self.pending_send {
                    self.pending_send = false;
                    if !self.input.is_empty() {
                        if let Err(e) = self.handle_input().await {
                            iron_error!("tui", "Error handling pending send: {}", e);
                        }
                        // Ensure input is cleared after sending
                        self.input.clear();
                        self.input_cursor = 0;
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

        // Setup file logging to ~/.ironchat.log
        self.setup_file_logging();

        // Create event stream
        let mut event_stream = EventStream::new();
        let mut message_count = 0u64;
        let mut last_message_time = std::time::Instant::now();
        let start_time = std::time::Instant::now();

        // Main event loop with error recovery
        let loop_result = async {
            while self.running {
                // Draw the UI - this is the key fix for borrow checker
                if let Err(e) = self.draw() {
                    iron_error!("tui", "🎨 Draw error: {}", e);
                    return Err(e);
                }

                // Handle events
                tokio::select! {
                    // Handle IRC messages
                    message_result = self.client.read_message() => {
                        match message_result {
                            Ok(Some(message)) => {
                                message_count += 1;
                                let now = std::time::Instant::now();
                                let _since_last = now.duration_since(last_message_time);
                                let _total_elapsed = now.duration_since(start_time);
                                last_message_time = now;
                                
                                // Process message without debug spam
                                
                                // Log the raw message only to file, not to Server tab UI
                                // self.add_log_message(&format!("📨 Received: {}", message.to_string().trim()));
                                
                                if let Err(e) = self.handle_irc_message(message).await {
                                    self.add_log_message(&format!("❌ Error handling message: {}", e));
                                }
                            }
                            Ok(None) => {
                                self.add_log_message(&format!("📡 Connection closed by server after {} messages", message_count));
                                break;
                            }
                            Err(e) => {
                                self.add_log_message(&format!("💥 Error reading message: {} (Final: {} messages in {:?})", 
                                                              e, message_count, start_time.elapsed()));
                                break;
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
                
                // Handle pending send from sidebar
                if self.pending_send {
                    self.pending_send = false;
                    if !self.input.is_empty() {
                        if let Err(e) = self.handle_input().await {
                            iron_error!("tui", "Error handling pending send: {}", e);
                        }
                        // Ensure input is cleared after sending
                        self.input.clear();
                        self.input_cursor = 0;
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

        self.terminal.draw(|f| {
            Self::draw_ui(f, &channels, &channel_order, current_tab, message_scroll, &input, input_cursor, show_help, show_sidebar, sidebar_selection, focus_mode, &user_context_menu, &keybindings);
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
        Self::draw_messages(f, main_chunks[0], channels, channel_order, current_tab, message_scroll, focus_mode);

        // Draw sidebar if enabled
        if show_sidebar && main_chunks.len() > 1 {
            Self::draw_sidebar(f, main_chunks[1], channels, channel_order, current_tab, sidebar_selection, focus_mode);
        }

        // Draw input with send button
        Self::draw_input_with_send(f, chunks[1], input, input_cursor, sidebar_selection);

        // Draw help overlay if enabled
        if show_help {
            Self::draw_help(f, keybindings);
        }
        
        // Draw user context menu if active
        if let Some(ref menu) = user_context_menu {
            Self::draw_user_context_menu(f, menu);
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
                        Style::default().fg(Color::Cyan)  // Bright cyan when focused on sidebar
                    } else {
                        Style::default().fg(Color::Gray)   // Gray when not focused
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
                    .map(|msg| Self::format_message(msg))
                    .map(ListItem::new)
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
                    Style::default().fg(Color::Cyan)  // Bright cyan when focused on input (chat scrolling)
                } else {
                    Style::default().fg(Color::Gray)  // Gray when not focused
                }
            );

        let messages_list = List::new(messages)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(messages_list, area);
    }


    fn draw_input_with_send(f: &mut Frame, area: Rect, input: &str, input_cursor: usize, sidebar_selection: usize) {
        // Split area for input field and send button
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20), Constraint::Length(12)])
            .split(area);
        
        // Draw input field
        let input_widget = Paragraph::new(input)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Input")
                .border_style(Style::default().fg(Color::Cyan)));
        
        f.render_widget(input_widget, chunks[0]);
        
        // Show cursor in input field
        f.set_cursor(
            chunks[0].x + input_cursor as u16 + 1,
            chunks[0].y + 1,
        );
        
        // Draw send button
        let send_text = "📤 Send";
        let is_send_focused = sidebar_selection == usize::MAX; // Special value for send button
        
        let send_style = if is_send_focused {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD).bg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        };
        
        let send_widget = Paragraph::new(send_text)
            .style(send_style)
            .block(Block::default().borders(Borders::ALL)
                .border_style(if is_send_focused { 
                    Style::default().fg(Color::Cyan) 
                } else { 
                    Style::default().fg(Color::Gray) 
                }))
            .alignment(ratatui::layout::Alignment::Center);
        
        f.render_widget(send_widget, chunks[1]);
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
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            .style(Style::default().bg(Color::Black));

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
            Line::from("  Up/Down - Navigate sidebar"),
            Line::from("  Enter - Select channel/user"),
            Line::from("  PageUp/PageDown - Scroll messages"),
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
            .block(Block::default().title("Help").borders(Borders::ALL))
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: true });

        f.render_widget(help, area);
    }

    fn format_message(msg: &DisplayMessage) -> Text<'static> {
        let timestamp = chrono::DateTime::<chrono::Local>::from(msg.timestamp)
            .format("%H:%M:%S")
            .to_string();

        match &msg.message_type {
            MessageType::Privmsg => {
                if let Some(ref sender) = msg.sender {
                    Text::from(Line::from(vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled(format!("<{}>", sender), Style::default().fg(Color::Green)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]))
                } else {
                    Text::from(Line::from(vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]))
                }
            }
            MessageType::Notice => {
                if let Some(ref sender) = msg.sender {
                    Text::from(Line::from(vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled(format!("-{}-", sender), Style::default().fg(Color::Yellow)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]))
                } else {
                    Text::from(Line::from(vec![
                        Span::styled(timestamp, Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::styled("***", Style::default().fg(Color::Yellow)),
                        Span::raw(" "),
                        Span::raw(msg.content.clone()),
                    ]))
                }
            }
            _ => {
                Text::from(Line::from(vec![
                    Span::styled(timestamp, Style::default().fg(Color::Gray)),
                    Span::raw(" "),
                    Span::styled("***", Style::default().fg(Color::Blue)),
                    Span::raw(" "),
                    Span::raw(msg.content.clone()),
                ]))
            }
        }
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
                    // Handle context menu first if it's open
                    if self.user_context_menu.is_some() {
                        return self.handle_context_menu_key(key.code).await;
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
                                        // Only allow left arrow if not on send button
                                        if self.sidebar_selection != usize::MAX {
                                            self.focus_mode = FocusMode::Input;
                                        }
                                    }
                                    KeyCode::Enter => self.sidebar_select(),
                                    KeyCode::Tab => self.handle_tab_completion(),
                                    _ => {} // Ignore other keys
                                }
                            }
                            FocusMode::Input => {
                                match key.code {
                                    KeyCode::Right if self.input_cursor == self.input.len() => {
                                        // If at end of input, go to sidebar
                                        self.focus_mode = FocusMode::Sidebar;
                                    }
                                    KeyCode::Up => self.scroll_up(),  // Page up
                                    KeyCode::Down => self.scroll_down(), // Page down
                                    KeyCode::PageUp => self.scroll_up(),
                                    KeyCode::PageDown => self.scroll_down(),
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
                    self.client.send_privmsg(&channel_name, &input).await?;
                    self.add_message(
                        &channel_name,
                        Some(self.client.current_nickname().to_string()),
                        input.clone(),
                        MessageType::Privmsg,
                    );
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
            _ => {
                self.add_system_message(&format!("Unknown command: {}. Type /help for available commands.", parts[0]));
            }
        }

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
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    let target = &message.params[0];
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Check if this is a private message (target is our nick)
                    let is_private_message = target == self.client.current_nickname();
                    
                    if is_private_message {
                        // Private message - create/use user tab
                        self.add_user_tab(sender.to_string());
                        self.add_message_with_timestamp(
                            sender,  // Use sender's nick as the tab name
                            Some(sender.to_string()),
                            content.clone(),
                            MessageType::Privmsg,
                            ActivityLevel::Mention,  // Private messages are always high priority
                            message.get_timestamp(),
                        );
                    } else {
                        // Channel message
                        let is_mention = content.contains(self.client.current_nickname());
                        let activity = if is_mention {
                            ActivityLevel::Mention
                        } else {
                            ActivityLevel::Message
                        };

                        self.add_message_with_timestamp(
                            target,
                            Some(sender.to_string()),
                            content.clone(),
                            MessageType::Privmsg,
                            activity,
                            message.get_timestamp(),
                        );
                    }
                }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("server");

                    self.add_message_with_timestamp(
                        "Server",
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Notice,
                        ActivityLevel::Message,
                        message.get_timestamp(),
                    );
                }
            }
            "JOIN" => {
                if let Some(channel) = message.params.get(0) {
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    if sender == self.client.current_nickname() {
                        self.add_channel(channel.clone());
                        self.switch_to_channel(channel);
                    } else {
                        if let Some(channel_data) = self.channels.get_mut(channel) {
                            channel_data.users.push(sender.to_string());
                        }
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
                                let nick = &message.params[1];
                                let user = &message.params[2];
                                let host = &message.params[3];
                                let realname = &message.params[5];
                                
                                let info = format!("WHOIS {}: {}@{} ({})", nick, user, host, realname);
                                self.add_message("Server", None, info, MessageType::Notice);
                            }
                        }
                        "312" => { // RPL_WHOISSERVER
                            if message.params.len() >= 4 {
                                let nick = &message.params[1];
                                let server = &message.params[2];
                                let server_info = &message.params[3];
                                
                                let info = format!("WHOIS {}: using server {} ({})", nick, server, server_info);
                                self.add_message("Server", None, info, MessageType::Notice);
                            }
                        }
                        "313" => { // RPL_WHOISOPERATOR
                            if message.params.len() >= 3 {
                                let nick = &message.params[1];
                                let info = format!("WHOIS {}: is an IRC operator", nick);
                                self.add_message("Server", None, info, MessageType::Notice);
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
                                
                                let info = format!("WHOIS {}: idle {} (signed on: {})", nick, idle_time, signon_date);
                                self.add_message("Server", None, info, MessageType::Notice);
                            }
                        }
                        "318" => { // RPL_ENDOFWHOIS
                            if message.params.len() >= 2 {
                                let nick = &message.params[1];
                                let info = format!("WHOIS {}: End of WHOIS list", nick);
                                self.add_message("Server", None, info, MessageType::Notice);
                            }
                        }
                        "319" => { // RPL_WHOISCHANNELS
                            if message.params.len() >= 3 {
                                let nick = &message.params[1];
                                let channels = &message.params[2];
                                let info = format!("WHOIS {}: channels {}", nick, channels);
                                self.add_message("Server", None, info, MessageType::Notice);
                            }
                        }
                        // Other WHOIS-related numerics that might be missing
                        "314" | "315" | "316" | "320" | "330" | "338" | "378" | "671" | "672" => {
                            if message.params.len() >= 2 {
                                let nick = &message.params[1];
                                let info = if message.params.len() >= 3 {
                                    message.params[2..].join(" ")
                                } else {
                                    "".to_string()
                                };
                                self.add_message("Server", None, format!("WHOIS {}: {}", nick, info), MessageType::Notice);
                            }
                        }
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
        if self.sidebar_selection == usize::MAX {
            // Coming from send button, go to last sidebar item
            self.sidebar_selection = self.get_total_sidebar_items() - 1;
            // Skip spacing if we land on it
            while self.is_spacing_item(self.sidebar_selection) && self.sidebar_selection > 0 {
                self.sidebar_selection -= 1;
            }
        } else if self.sidebar_selection > 0 {
            self.sidebar_selection -= 1;
            // Skip spacing if we land on it
            while self.is_spacing_item(self.sidebar_selection) && self.sidebar_selection > 0 {
                self.sidebar_selection -= 1;
            }
        }
    }

    fn sidebar_down(&mut self) {
        let max_items = self.get_total_sidebar_items();
        if self.sidebar_selection < max_items - 1 {
            self.sidebar_selection += 1;
            // Skip spacing if we land on it
            while self.is_spacing_item(self.sidebar_selection) && self.sidebar_selection < max_items - 1 {
                self.sidebar_selection += 1;
            }
        } else if self.sidebar_selection == max_items - 1 {
            // Jump to send button
            self.sidebar_selection = usize::MAX;
        }
    }

    fn sidebar_jump_to_send(&mut self) {
        // Only jump if we're not already at the send button
        if self.sidebar_selection != usize::MAX {
            self.previous_sidebar_selection = self.sidebar_selection;
            self.sidebar_selection = usize::MAX;
        }
    }

    fn sidebar_return_from_send(&mut self) {
        // Only return if we're currently at the send button
        if self.sidebar_selection == usize::MAX {
            self.sidebar_selection = self.previous_sidebar_selection;
        }
    }

    fn is_spacing_item(&self, index: usize) -> bool {
        matches!(self.get_sidebar_item_type(index), SidebarItemType::Spacing)
    }

    fn sidebar_select(&mut self) {
        // Handle send button selection
        if self.sidebar_selection == usize::MAX {
            self.sidebar_send_message();
            return;
        }
        
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

    fn sidebar_send_message(&mut self) {
        // Send the current input if it's not empty
        if !self.input.is_empty() {
            // Create a fake event to trigger message sending
            // We'll handle this in the main event loop
            self.pending_send = true;
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

    async fn handle_context_menu_key(&mut self, key_code: KeyCode) -> Result<()> {
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

    fn scroll_up(&mut self) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                let total_messages = channel.messages.len();
                if total_messages > 0 {
                    // We can scroll up to a maximum where we show the first message at the top
                    // This prevents scrolling beyond the beginning of the message list
                    let max_scroll = total_messages.saturating_sub(1);
                    self.message_scroll = (self.message_scroll + 10).min(max_scroll);
                }
            }
        }
    }

    fn scroll_down(&mut self) {
        // Scroll down to newer messages (decrease scroll offset)
        self.message_scroll = self.message_scroll.saturating_sub(10);
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
                "/join", "/part", "/quit", "/nick", "/msg", "/raw", "/help",
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
        let log_path = format!("{}/.ironchat.log", home_dir);
        
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

    fn add_message_with_timestamp(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel, timestamp: SystemTime) {
        let message = DisplayMessage {
            timestamp,
            sender,
            content: Self::strip_irc_formatting(&content),
            message_type: msg_type,
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