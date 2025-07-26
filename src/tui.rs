use crate::client::IronClient;
use crate::message::IrcMessage;
use crate::error::Result;
use crate::config::{Config, KeybindingsConfig};

use std::collections::HashMap;
use std::time::SystemTime;
use std::io;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use futures::StreamExt;
use tracing::{debug, info, error};

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
    sidebar_selection: usize,  // Index in combined sidebar list
    channel_users_expanded: HashMap<String, bool>,  // Track which channels have users expanded
    running: bool,
    
    // Config
    keybindings: KeybindingsConfig,
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
    Quit,
    Nick,
    Topic,
    System,
}

#[derive(Debug, Clone)]
struct TabCompletionState {
    original_input: String,
    original_cursor: usize,
    completions: Vec<String>,
    current_index: usize,
    completion_start: usize,
}

impl IrcTui {
    pub fn new(client: IronClient, config: &Config) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
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
            sidebar_selection: 0,
            channel_users_expanded: HashMap::new(),
            running: false,
            keybindings: config.keybindings.clone(),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting IronChat TUI");
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

        // Main event loop
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
                                error!("Error handling IRC message: {}", e);
                            }
                        }
                        Ok(None) => {
                            info!("Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            error!("Error reading message: {}", e);
                            break;
                        }
                    }
                }
                
                // Handle keyboard events
                maybe_event = event_stream.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            if let Err(e) = self.handle_event(event).await {
                                error!("Error handling event: {}", e);
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading event: {}", e);
                        }
                        None => break,
                    }
                }
            }
        }

        self.cleanup()?;
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
        let keybindings = self.keybindings.clone();

        self.terminal.draw(|f| {
            Self::draw_ui(f, &channels, &channel_order, current_tab, message_scroll, &input, input_cursor, show_help, show_sidebar, sidebar_selection, &keybindings);
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
        Self::draw_messages(f, main_chunks[0], channels, channel_order, current_tab, message_scroll);

        // Draw sidebar if enabled
        if show_sidebar && main_chunks.len() > 1 {
            Self::draw_sidebar(f, main_chunks[1], channels, channel_order, current_tab, sidebar_selection);
        }

        // Draw input
        Self::draw_input(f, chunks[1], input, input_cursor);

        // Draw help overlay if enabled
        if show_help {
            Self::draw_help(f, keybindings);
        }
    }

    fn draw_sidebar(
        f: &mut Frame,
        area: Rect,
        channels: &HashMap<String, ChannelData>,
        channel_order: &[String],
        current_tab: usize,
        sidebar_selection: usize,
    ) {
        let mut items = Vec::new();
        let mut item_index = 0;
        
        // Add channels section
        items.push(ListItem::new(Line::from(vec![
            Span::styled("Channels", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        ])));
        
        // Add each channel
        for (i, chan_name) in channel_order.iter().enumerate() {
            item_index += 1;
            let is_selected = item_index == sidebar_selection;
            let is_current = i == current_tab;
            
            let channel = &channels[chan_name];
            let style = if is_current {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                match channel.activity {
                    ActivityLevel::Mention => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ActivityLevel::Message => Style::default().fg(Color::White),
                    ActivityLevel::None => Style::default().fg(Color::DarkGray),
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
        
        // Add spacing
        items.push(ListItem::new(""));
        
        // Add users section for current channel if it has users
        if let Some(current_chan_name) = channel_order.get(current_tab) {
            if let Some(channel) = channels.get(current_chan_name) {
                if !channel.users.is_empty() {
                    item_index += 1;
                    let is_selected = item_index == sidebar_selection;
                    let expanded = channel.users_expanded;
                    
                    // Users header with expand/collapse indicator
                    let indicator = if expanded { "▼" } else { "▶" };
                    let user_count = channel.users.len();
                    let header_text = format!("{} Users ({})", indicator, user_count);
                    
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
                            let is_selected = item_index == sidebar_selection;
                            
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
                .title("Sidebar"));
        
        f.render_widget(list, area);
    }

    fn draw_messages(
        f: &mut Frame,
        area: Rect,
        channels: &HashMap<String, ChannelData>,
        channel_order: &[String],
        current_tab: usize,
        scroll_offset: usize,
    ) {
        let current_channel = channel_order.get(current_tab)
            .and_then(|name| channels.get(name));
        
        let messages: Vec<ListItem> = if let Some(channel) = current_channel {
            let total_messages = channel.messages.len();
            let visible_height = area.height.saturating_sub(2) as usize; // Subtract border height
            
            // Calculate which messages to show based on scroll
            let end_index = total_messages.saturating_sub(scroll_offset);
            let start_index = end_index.saturating_sub(visible_height);
            
            channel.messages[start_index..end_index].iter()
                .map(|msg| Self::format_message(msg))
                .map(ListItem::new)
                .collect()
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

        let block = Block::default().borders(Borders::ALL).title(title);

        let messages_list = List::new(messages)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(messages_list, area);
    }


    fn draw_input(f: &mut Frame, area: Rect, input: &str, input_cursor: usize) {
        let input_widget = Paragraph::new(input)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Input"));
        
        f.render_widget(input_widget, area);

        // Show cursor
        f.set_cursor(
            area.x + input_cursor as u16 + 1,
            area.y + 1,
        );
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
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    async fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Press {
                    // Check custom keybindings first
                    if self.keybindings.matches_key(&self.keybindings.quit, key.code, key.modifiers) {
                        self.running = false;
                    } else if self.keybindings.matches_key(&self.keybindings.toggle_help, key.code, key.modifiers) {
                        self.show_help = !self.show_help;
                    } else if self.keybindings.matches_key(&self.keybindings.toggle_users, key.code, key.modifiers) {
                        self.show_sidebar = !self.show_sidebar;
                    } else if key.code == KeyCode::Up && key.modifiers.is_empty() {
                        self.sidebar_up();
                    } else if key.code == KeyCode::Down && key.modifiers.is_empty() {
                        self.sidebar_down();
                    } else if key.code == KeyCode::Enter && key.modifiers.is_empty() {
                        self.sidebar_select();
                    } else if key.code == KeyCode::Tab {
                        // Tab always does completion
                        self.handle_tab_completion();
                    } else if key.code == KeyCode::PageUp {
                        self.scroll_up();
                    } else if key.code == KeyCode::PageDown {
                        self.scroll_down();
                    } else {
                        // Handle other keys
                        match key.code {
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
                    }
                }
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
        debug!("Received IRC message: {} from {:?}", message.command, message.prefix);

        match message.command.as_str() {
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    let target = &message.params[0];
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Determine if it's a mention
                    let is_mention = content.contains(self.client.current_nickname());
                    let activity = if is_mention {
                        ActivityLevel::Mention
                    } else {
                        ActivityLevel::Message
                    };

                    self.add_message_with_activity(
                        target,
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Privmsg,
                        activity,
                    );
                }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("server");

                    self.add_message(
                        "Server",
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Notice,
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
            "PING" | "PONG" | "ERROR" | "433" | "436" => {
                // Forward protocol messages to client for handling
                if let Err(e) = self.client.handle_message(message).await {
                    error!("Error handling protocol message: {}", e);
                }
            }
            _ => {
                // Forward to client and log unhandled types
                debug!("Unhandled IRC message type: {} with params: {:?}", message.command, message.params);
                
                if let Err(e) = self.client.handle_message(message).await {
                    error!("Error forwarding message to client: {}", e);
                }
            }
        }

        Ok(())
    }

    // Helper methods
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

    fn next_tab(&mut self) {
        if !self.channel_order.is_empty() {
            self.current_tab = (self.current_tab + 1) % self.channel_order.len();
            self.mark_current_as_read();
            self.message_scroll = 0; // Reset scroll when switching tabs
        }
    }

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

    fn sidebar_up(&mut self) {
        if self.sidebar_selection > 0 {
            self.sidebar_selection -= 1;
        }
    }

    fn sidebar_down(&mut self) {
        // Calculate max selection index
        let channel_count = self.channel_order.len() + 1; // +1 for "Channels" header
        let user_section_count = if let Some(chan_name) = self.channel_order.get(self.current_tab) {
            self.channels.get(chan_name).map_or(0, |c| {
                if c.users.is_empty() {
                    0
                } else if c.users_expanded {
                    c.users.len() + 1 // +1 for "Users" header
                } else {
                    1 // Just the header
                }
            })
        } else {
            0
        };
        let max_selection = channel_count + user_section_count + (if user_section_count > 0 { 1 } else { 0 }); // +1 for spacing
        
        if self.sidebar_selection < max_selection - 1 {
            self.sidebar_selection += 1;
        }
    }

    fn sidebar_select(&mut self) {
        // Check if we're selecting a channel
        if self.sidebar_selection > 0 && self.sidebar_selection <= self.channel_order.len() {
            let new_tab = self.sidebar_selection - 1;
            if new_tab != self.current_tab {
                self.current_tab = new_tab;
                self.message_scroll = 0;
                self.mark_current_as_read();
            }
        } else {
            // Check if we're selecting the users header
            let channel_count = self.channel_order.len() + 1; // +1 for "Channels" header  
            let users_header_index = channel_count + 1; // +1 for spacing
            
            if self.sidebar_selection == users_header_index {
                // Toggle users expansion for current channel
                if let Some(chan_name) = self.get_current_channel_name() {
                    if let Some(channel) = self.channels.get_mut(&chan_name) {
                        if !channel.users.is_empty() {
                            channel.users_expanded = !channel.users_expanded;
                        }
                    }
                }
            }
            // TODO: Handle individual user selection for whois/query
        }
    }

    fn scroll_up(&mut self) {
        if let Some(channel_name) = self.get_current_channel_name() {
            if let Some(channel) = self.channels.get(&channel_name) {
                let max_scroll = channel.messages.len().saturating_sub(1);
                self.message_scroll = (self.message_scroll + 10).min(max_scroll);
            }
        }
    }

    fn scroll_down(&mut self) {
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

    fn add_message(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType) {
        self.add_message_with_activity(channel, sender, content, msg_type, ActivityLevel::Message);
    }

    fn add_message_with_activity(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType, activity: ActivityLevel) {
        let message = DisplayMessage {
            timestamp: SystemTime::now(),
            sender,
            content,
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
        let _ = self.cleanup();
    }
}