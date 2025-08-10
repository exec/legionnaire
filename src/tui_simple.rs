use crate::client::IronClient;
use legion_protocol::IrcMessage;
use crate::error::Result;

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
use crate::{iron_debug, iron_info, iron_error};

pub struct IrcTui {
    client: IronClient,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    
    // Channel state
    channels: HashMap<String, ChannelData>,
    channel_order: Vec<String>,
    current_tab: usize,
    
    // Input state
    input: String,
    input_cursor: usize,
    
    // UI state
    show_help: bool,
    show_users: bool,
    running: bool,
}

#[derive(Debug, Clone)]
struct ChannelData {
    name: String,
    messages: Vec<DisplayMessage>,
    users: Vec<String>,
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

impl IrcTui {
    pub fn new(client: IronClient) -> Result<Self> {
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
            input: String::new(),
            input_cursor: 0,
            show_help: false,
            show_users: false,
            running: false,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        iron_info!("tui_simple", "Starting IronChat TUI");
        self.running = true;

        // Connect to IRC
        self.client.connect().await?;
        
        // Create initial server tab
        self.add_channel("Server".to_string());
        self.add_system_message("Connected to IRC server");
        self.add_system_message("Type /help for commands, F1 to toggle help panel");

        // Create event stream
        let mut event_stream = EventStream::new();

        // Main event loop
        while self.running {
            // Draw the UI
            self.draw()?;

            // Handle events
            tokio::select! {
                // Handle IRC messages
                message_result = self.client.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            if let Err(e) = self.handle_irc_message(message).await {
                                iron_error!("tui_simple", "Error handling IRC message: {}", e);
                            }
                        }
                        Ok(None) => {
                            iron_info!("tui_simple", "Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            iron_error!("tui_simple", "Error reading message: {}", e);
                            break;
                        }
                    }
                }
                
                // Handle keyboard events
                maybe_event = event_stream.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            if let Err(e) = self.handle_event(event).await {
                                iron_error!("tui_simple", "Error handling event: {}", e);
                            }
                        }
                        Some(Err(e)) => {
                            iron_error!("tui_simple", "Error reading event: {}", e);
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
        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Tabs
                    Constraint::Min(1),    // Main area
                    Constraint::Length(3), // Input
                ])
                .split(f.size());

            // Draw tabs
            self.draw_tabs(f, chunks[0]);

            // Split main area for user list
            let main_chunks = if self.show_users {
                Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(75), Constraint::Percentage(25)])
                    .split(chunks[1])
                    .to_vec()
            } else {
                vec![chunks[1]]
            };

            // Draw messages
            self.draw_messages(f, main_chunks[0]);

            // Draw user list if enabled
            if self.show_users && main_chunks.len() > 1 {
                self.draw_users(f, main_chunks[1]);
            }

            // Draw input
            self.draw_input(f, chunks[2]);

            // Draw help overlay if enabled
            if self.show_help {
                self.draw_help(f);
            }
        })?;
        Ok(())
    }

    fn draw_tabs(&self, f: &mut Frame, area: Rect) {
        let titles: Vec<Line> = self.channel_order
            .iter()
            .map(|name| {
                let channel = &self.channels[name];
                let mut spans = vec![Span::raw(name.clone())];
                
                if channel.unread_count > 0 {
                    spans.push(Span::styled(
                        format!(" ({})", channel.unread_count),
                        Style::default().fg(match channel.activity {
                            ActivityLevel::Mention => Color::Red,
                            ActivityLevel::Message => Color::Yellow,
                            ActivityLevel::None => Color::Gray,
                        })
                    ));
                }
                
                Line::from(spans)
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("Channels")
                .border_style(Style::default().fg(Color::DarkGray)))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .select(self.current_tab);

        f.render_widget(tabs, area);
    }

    fn draw_messages(&self, f: &mut Frame, area: Rect) {
        let current_channel = self.get_current_channel();
        
        let messages: Vec<ListItem> = if let Some(channel) = current_channel {
            channel.messages.iter()
                .map(|msg| self.format_message(msg))
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

        let messages_list = List::new(messages)
            .block(Block::default().borders(Borders::ALL).title(title)
                .border_style(Style::default().fg(Color::DarkGray)))
            .style(Style::default().fg(Color::White));

        f.render_widget(messages_list, area);
    }

    fn draw_users(&self, f: &mut Frame, area: Rect) {
        let current_channel = self.get_current_channel();
        
        let users: Vec<ListItem> = if let Some(channel) = current_channel {
            channel.users.iter()
                .map(|user| ListItem::new(user.as_str()))
                .collect()
        } else {
            vec![]
        };

        let users_list = List::new(users)
            .block(Block::default().borders(Borders::ALL).title("Users")
                .border_style(Style::default().fg(Color::DarkGray)))
            .style(Style::default().fg(Color::White));

        f.render_widget(users_list, area);
    }

    fn draw_input(&self, f: &mut Frame, area: Rect) {
        let input = Paragraph::new(self.input.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Input")
                .border_style(Style::default().fg(Color::DarkGray)));
        
        f.render_widget(input, area);

        // Show cursor
        f.set_cursor(
            area.x + self.input_cursor as u16 + 1,
            area.y + 1,
        );
    }

    fn draw_help(&self, f: &mut Frame) {
        let area = Rect {
            x: f.size().width / 4,
            y: f.size().height / 4,
            width: f.size().width / 2,
            height: f.size().height / 2,
        };

        f.render_widget(Clear, area);

        let help_text = vec![
            Line::from("IronChat Help"),
            Line::from(""),
            Line::from("Tab Navigation:"),
            Line::from("  Tab/Shift+Tab - Switch channels"),
            Line::from(""),
            Line::from("Commands:"),
            Line::from("  /join <channel>  - Join channel"),
            Line::from("  /part [channel]  - Leave channel"),
            Line::from("  /nick <nick>     - Change nickname"),
            Line::from("  /msg <user> <msg> - Private message"),
            Line::from("  /quit [reason]   - Quit IRC"),
            Line::from(""),
            Line::from("Keys:"),
            Line::from("  F1 - Toggle this help"),
            Line::from("  F2 - Toggle user list"),
            Line::from("  Esc - Quit"),
        ];

        let help = Paragraph::new(help_text)
            .block(Block::default().title("Help").borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)))
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: true });

        f.render_widget(help, area);
    }

    fn format_message(&self, msg: &DisplayMessage) -> Text<'static> {
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
                    match key.code {
                        KeyCode::Esc => {
                            self.running = false;
                        }
                        KeyCode::F(1) => {
                            self.show_help = !self.show_help;
                        }
                        KeyCode::F(2) => {
                            self.show_users = !self.show_users;
                        }
                        KeyCode::Tab => {
                            self.next_tab();
                        }
                        KeyCode::BackTab => {
                            self.prev_tab();
                        }
                        KeyCode::Enter => {
                            self.handle_input().await?;
                        }
                        KeyCode::Backspace => {
                            if !self.input.is_empty() && self.input_cursor > 0 {
                                self.input.remove(self.input_cursor - 1);
                                self.input_cursor -= 1;
                            }
                        }
                        KeyCode::Left => {
                            if self.input_cursor > 0 {
                                self.input_cursor -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if self.input_cursor < self.input.len() {
                                self.input_cursor += 1;
                            }
                        }
                        KeyCode::Home => {
                            self.input_cursor = 0;
                        }
                        KeyCode::End => {
                            self.input_cursor = self.input.len();
                        }
                        KeyCode::Char(c) => {
                            self.input.insert(self.input_cursor, c);
                            self.input_cursor += 1;
                        }
                        _ => {}
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
            _ => {
                self.add_system_message(&format!("Unknown command: {}. Type /help for available commands.", parts[0]));
            }
        }

        Ok(())
    }

    async fn handle_irc_message(&mut self, message: IrcMessage) -> Result<()> {
        iron_debug!("tui_simple", "Received IRC message: {} from {:?}", message.command, message.prefix);

        match message.command.as_str() {
            "PRIVMSG" => {
                if message.params.len() >= 2 {
                    let target = &message.params[0];
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    self.add_message(
                        target,
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Privmsg,
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
                    }

                    self.add_message(
                        channel,
                        None,
                        format!("{} joined {}", sender, channel),
                        MessageType::Join,
                    );
                }
            }
            _ => {
                // Forward other messages to client
                if let Err(e) = self.client.handle_message(message).await {
                    iron_error!("tui_simple", "Error forwarding message to client: {}", e);
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
                topic: None,
                unread_count: 0,
                activity: ActivityLevel::None,
            });
            self.channel_order.push(name);
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

    fn get_current_channel(&self) -> Option<&ChannelData> {
        self.channel_order.get(self.current_tab)
            .and_then(|name| self.channels.get(name))
    }

    fn get_current_channel_name(&self) -> Option<String> {
        self.channel_order.get(self.current_tab).cloned()
    }

    fn add_system_message(&mut self, content: &str) {
        self.add_message("Server", None, content.to_string(), MessageType::System);
    }

    fn add_message(&mut self, channel: &str, sender: Option<String>, content: String, msg_type: MessageType) {
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
                channel_data.activity = ActivityLevel::Message;
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