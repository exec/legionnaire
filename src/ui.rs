use crate::client::IronClient;
use crate::message::IrcMessage;
use crate::error::{IronError, Result};

use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::time::SystemTime;
use tracing::{debug, info, warn, error};

pub struct IrcUi {
    client: IronClient,
    message_buffer: Vec<DisplayMessage>,
    current_channel: Option<String>,
    channels: HashMap<String, ChannelState>,
    command_tx: mpsc::UnboundedSender<UserCommand>,
    command_rx: mpsc::UnboundedReceiver<UserCommand>,
    running: bool,
}

#[derive(Debug, Clone)]
struct DisplayMessage {
    timestamp: SystemTime,
    channel: Option<String>,
    sender: Option<String>,
    content: String,
    message_type: MessageType,
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
    Mode,
    System,
}

#[derive(Debug, Clone)]
struct ChannelState {
    topic: Option<String>,
    users: Vec<String>,
    joined: bool,
}

#[derive(Debug)]
enum UserCommand {
    Join(String),
    Part(String, Option<String>),
    Message(String, String),
    Nick(String),
    Quit(Option<String>),
    List,
    Switch(String),
    Help,
    Raw(String),
}

impl IrcUi {
    pub fn new(client: IronClient) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        
        Self {
            client,
            message_buffer: Vec::new(),
            current_channel: None,
            channels: HashMap::new(),
            command_tx,
            command_rx,
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting IronChat UI");
        self.running = true;

        self.client.connect().await?;
        
        self.print_welcome();
        self.print_help();

        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);

        loop {
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
                
                // Handle user input
                input_result = async {
                    let mut input = String::new();
                    reader.read_line(&mut input).await.map(|_| input)
                } => {
                    match input_result {
                        Ok(input) => {
                            let trimmed = input.trim();
                            if !trimmed.is_empty() {
                                self.handle_user_input(trimmed).await?;
                            }
                        }
                        Err(e) => {
                            error!("Error reading user input: {}", e);
                            break;
                        }
                    }
                }
                
                // Handle commands from command queue
                command = self.command_rx.recv() => {
                    if let Some(cmd) = command {
                        if let Err(e) = self.handle_command(cmd).await {
                            self.print_error(&format!("Command error: {}", e));
                        }
                    }
                }
            }

            if !self.running {
                break;
            }
        }

        self.client.disconnect().await?;
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

                    self.display_message(
                        Some(target.clone()),
                        Some(sender.to_string()),
                        content.clone(),
                        MessageType::Privmsg,
                    );
                }
            }
            "NOTICE" => {
                if message.params.len() >= 2 {
                    let content = &message.params[1];
                    let sender = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("server");

                    self.display_message(
                        None,
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
                        self.channels.insert(channel.clone(), ChannelState {
                            topic: None,
                            users: Vec::new(),
                            joined: true,
                        });
                        if self.current_channel.is_none() {
                            self.current_channel = Some(channel.clone());
                        }
                    } else {
                        if let Some(chan_state) = self.channels.get_mut(channel) {
                            chan_state.users.push(sender.to_string());
                        }
                    }

                    self.display_message(
                        Some(channel.clone()),
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
                        self.channels.remove(channel);
                        if self.current_channel.as_ref() == Some(channel) {
                            self.current_channel = self.channels.keys().next().cloned();
                        }
                    } else {
                        if let Some(chan_state) = self.channels.get_mut(channel) {
                            chan_state.users.retain(|u| u != sender);
                        }
                    }

                    let reason = message.params.get(1).map(|r| format!(" ({})", r)).unwrap_or_default();
                    self.display_message(
                        Some(channel.clone()),
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
                    
                    if let Some(chan_state) = self.channels.get_mut(channel) {
                        for name in names.split_whitespace() {
                            let clean_name = name.trim_start_matches(['@', '+', '%', '&', '~']);
                            if !chan_state.users.contains(&clean_name.to_string()) {
                                chan_state.users.push(clean_name.to_string());
                            }
                        }
                    }
                }
            }
            "332" => { // Topic
                if message.params.len() >= 3 {
                    let channel = &message.params[1];
                    let topic = &message.params[2];
                    
                    if let Some(chan_state) = self.channels.get_mut(channel) {
                        chan_state.topic = Some(topic.clone());
                    }

                    self.display_message(
                        Some(channel.clone()),
                        None,
                        format!("Topic: {}", topic),
                        MessageType::Topic,
                    );
                }
            }
            "NICK" => {
                if let Some(new_nick) = message.params.get(0) {
                    let old_nick = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Update user lists in channels
                    for chan_state in self.channels.values_mut() {
                        if let Some(pos) = chan_state.users.iter().position(|u| u == old_nick) {
                            chan_state.users[pos] = new_nick.clone();
                        }
                    }

                    self.display_message(
                        None,
                        None,
                        format!("{} is now known as {}", old_nick, new_nick),
                        MessageType::Nick,
                    );
                }

                // Forward to client for nickname tracking
                if let Err(e) = self.client.handle_message(message).await {
                    error!("Error handling NICK message: {}", e);
                }
            }
            "QUIT" => {
                if let Some(reason) = message.params.get(0) {
                    let user = message.prefix.as_ref()
                        .and_then(|s| s.split('!').next())
                        .unwrap_or("unknown");

                    // Remove user from all channel lists
                    for chan_state in self.channels.values_mut() {
                        chan_state.users.retain(|u| u != user);
                    }

                    self.display_message(
                        None,
                        None,
                        format!("{} has quit ({})", user, reason),
                        MessageType::Quit,
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
                // For other messages, handle them and then forward to client
                // Log unhandled message types for visibility
                debug!("Unhandled IRC message type: {} with params: {:?}", message.command, message.params);
                
                // Forward to client in case it needs to handle it
                if let Err(e) = self.client.handle_message(message).await {
                    error!("Error forwarding message to client: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_user_input(&mut self, input: &str) -> Result<()> {
        if input.is_empty() {
            return Ok(());
        }

        if input.starts_with('/') {
            self.parse_command(&input[1..]).await?;
        } else {
            // Send message to current channel
            if let Some(ref channel) = self.current_channel.clone() {
                self.client.send_privmsg(channel, input).await?;
                self.display_message(
                    Some(channel.clone()),
                    Some(self.client.current_nickname().to_string()),
                    input.to_string(),
                    MessageType::Privmsg,
                );
            } else {
                self.print_error("No active channel. Use /join <channel> first.");
            }
        }

        Ok(())
    }

    async fn parse_command(&mut self, input: &str) -> Result<()> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        let command = match parts[0].to_lowercase().as_str() {
            // IRC service aliases
            "ns" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /ns <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("NickServ".to_string(), message)
            }
            "cs" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /cs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("ChanServ".to_string(), message)
            }
            "ms" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /ms <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("MemoServ".to_string(), message)
            }
            "os" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /os <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("OperServ".to_string(), message)
            }
            "hs" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /hs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("HostServ".to_string(), message)
            }
            "bs" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /bs <command>");
                    return Ok(());
                }
                let message = parts[1..].join(" ");
                UserCommand::Message("BotServ".to_string(), message)
            }
            // Regular commands
            "join" | "j" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /join <channel>");
                    return Ok(());
                }
                let channel = if parts[1].starts_with('#') {
                    parts[1].to_string()
                } else {
                    format!("#{}", parts[1])
                };
                UserCommand::Join(channel)
            }
            "part" | "leave" => {
                let channel = if parts.len() > 1 {
                    parts[1].to_string()
                } else if let Some(ref current) = self.current_channel {
                    current.clone()
                } else {
                    self.print_error("No channel specified and no active channel");
                    return Ok(());
                };
                let reason = if parts.len() > 2 {
                    Some(parts[2..].join(" "))
                } else {
                    None
                };
                UserCommand::Part(channel, reason)
            }
            "msg" | "privmsg" => {
                if parts.len() < 3 {
                    self.print_error("Usage: /msg <target> <message>");
                    return Ok(());
                }
                let target = parts[1].to_string();
                let message = parts[2..].join(" ");
                UserCommand::Message(target, message)
            }
            "nick" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /nick <nickname>");
                    return Ok(());
                }
                UserCommand::Nick(parts[1].to_string())
            }
            "quit" | "exit" => {
                let reason = if parts.len() > 1 {
                    Some(parts[1..].join(" "))
                } else {
                    None
                };
                UserCommand::Quit(reason)
            }
            "list" | "channels" => UserCommand::List,
            "switch" | "s" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /switch <channel>");
                    return Ok(());
                }
                UserCommand::Switch(parts[1].to_string())
            }
            "help" | "h" => UserCommand::Help,
            "raw" => {
                if parts.len() < 2 {
                    self.print_error("Usage: /raw <IRC command>");
                    return Ok(());
                }
                UserCommand::Raw(parts[1..].join(" "))
            }
            _ => {
                self.print_error(&format!("Unknown command: {}. Type /help for available commands.", parts[0]));
                return Ok(());
            }
        };

        self.handle_command(command).await
    }

    async fn handle_command(&mut self, command: UserCommand) -> Result<()> {
        match command {
            UserCommand::Join(channel) => {
                self.client.join_channel(&channel).await?;
                self.print_info(&format!("Joining {}", channel));
            }
            UserCommand::Part(channel, reason) => {
                self.client.part_channel(&channel, reason.as_deref()).await?;
                self.print_info(&format!("Leaving {}", channel));
            }
            UserCommand::Message(target, message) => {
                self.client.send_privmsg(&target, &message).await?;
                self.display_message(
                    Some(target.clone()),
                    Some(self.client.current_nickname().to_string()),
                    message,
                    MessageType::Privmsg,
                );
            }
            UserCommand::Nick(nick) => {
                let nick_msg = IrcMessage::new("NICK").with_params(vec![nick.clone()]);
                self.client.send_message(&nick_msg).await?;
                self.print_info(&format!("Changing nickname to {}", nick));
            }
            UserCommand::Quit(reason) => {
                self.running = false;
                if let Some(reason) = reason {
                    self.print_info(&format!("Quitting: {}", reason));
                } else {
                    self.print_info("Quitting");
                }
            }
            UserCommand::List => {
                self.print_channels();
            }
            UserCommand::Switch(channel) => {
                if self.channels.contains_key(&channel) {
                    self.current_channel = Some(channel.clone());
                    self.print_info(&format!("Switched to {}", channel));
                } else {
                    self.print_error(&format!("Not in channel {}", channel));
                }
            }
            UserCommand::Help => {
                self.print_help();
            }
            UserCommand::Raw(command) => {
                self.client.send_raw(&command).await?;
                self.print_info(&format!("Sent raw: {}", command));
            }
        }

        Ok(())
    }

    fn display_message(&mut self, channel: Option<String>, sender: Option<String>, content: String, msg_type: MessageType) {
        let display_msg = DisplayMessage {
            timestamp: SystemTime::now(),
            channel: channel.clone(),
            sender: sender.clone(),
            content: content.clone(),
            message_type: msg_type,
        };

        let msg_type = display_msg.message_type.clone();
        self.message_buffer.push(display_msg);

        // Format and print the message
        let timestamp = chrono::DateTime::<chrono::Local>::from(SystemTime::now())
            .format("%H:%M:%S");

        let channel_prefix = if let Some(ref chan) = channel {
            if Some(chan) == self.current_channel.as_ref() {
                format!("[{}] ", chan)
            } else {
                format!("[{}] ", chan)
            }
        } else {
            String::new()
        };

        match msg_type {
            MessageType::Privmsg => {
                if let Some(sender) = sender {
                    println!("{} {}<{}> {}", timestamp, channel_prefix, sender, content);
                }
            }
            MessageType::Notice => {
                if let Some(sender) = sender {
                    println!("{} {}*{}* {}", timestamp, channel_prefix, sender, content);
                }
            }
            MessageType::Join | MessageType::Part | MessageType::Quit | MessageType::Nick => {
                println!("{} {}*** {}", timestamp, channel_prefix, content);
            }
            MessageType::Topic => {
                println!("{} {}*** {}", timestamp, channel_prefix, content);
            }
            MessageType::System => {
                println!("{} *** {}", timestamp, content);
            }
            _ => {
                println!("{} {} {}", timestamp, channel_prefix, content);
            }
        }
    }

    fn print_welcome(&self) {
        println!("=== IronChat - Security-Hardened IRCv3 Client ===");
        println!("Connected as: {}", self.client.current_nickname());
        println!("Type /help for available commands");
        println!("===============================================");
    }

    fn print_help(&self) {
        println!("Available commands:");
        println!("  /join <channel>           - Join a channel");
        println!("  /part [channel] [reason]  - Leave a channel");
        println!("  /msg <target> <message>   - Send private message");
        println!("  /nick <nickname>          - Change nickname");
        println!("  /switch <channel>         - Switch active channel");
        println!("  /list                     - List joined channels");
        println!("  /raw <command>            - Send raw IRC command");
        println!("  /quit [reason]            - Quit IRC");
        println!("  /help                     - Show this help");
        println!();
        println!("Service aliases:");
        println!("  /ns <command>             - Send command to NickServ");
        println!("  /cs <command>             - Send command to ChanServ");
        println!("  /ms <command>             - Send command to MemoServ");
        println!("  /os <command>             - Send command to OperServ");
        println!("  /hs <command>             - Send command to HostServ");
        println!("  /bs <command>             - Send command to BotServ");
        println!();
        println!("To send a message, just type without a command prefix.");
    }

    fn print_channels(&self) {
        println!("Joined channels:");
        for (channel, state) in &self.channels {
            let current = if Some(channel) == self.current_channel.as_ref() { " (current)" } else { "" };
            let topic = state.topic.as_ref().map(|t| format!(" - {}", t)).unwrap_or_default();
            println!("  {}{}{} ({} users)", channel, current, topic, state.users.len());
        }
    }

    fn print_info(&self, message: &str) {
        let timestamp = chrono::DateTime::<chrono::Local>::from(SystemTime::now())
            .format("%H:%M:%S");
        println!("{} *** {}", timestamp, message);
    }

    fn print_error(&self, message: &str) {
        let timestamp = chrono::DateTime::<chrono::Local>::from(SystemTime::now())
            .format("%H:%M:%S");
        eprintln!("{} ERROR: {}", timestamp, message);
    }
}