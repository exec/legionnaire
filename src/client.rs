use crate::connection::SecureConnection;
use crate::message::IrcMessage;
use crate::capabilities::CapabilityHandler;
use crate::auth::SaslAuthenticator;
use crate::error::{IronError, Result};

use tokio::sync::mpsc;
use std::time::Duration;
use tracing::{debug, info, warn, error};
use secrecy::SecretString;

#[derive(Debug, Clone)]
pub struct IrcConfig {
    pub server: String,
    pub port: u16,
    pub nickname: String,
    pub username: String,
    pub realname: String,
    pub channels: Vec<String>,
    pub tls_required: bool,
    pub verify_certificates: bool,
    pub connection_timeout: Duration,
    pub ping_timeout: Duration,
    pub reconnect_attempts: u32,
    pub reconnect_delay: Duration,
}

impl Default for IrcConfig {
    fn default() -> Self {
        Self {
            server: "irc.libera.chat".to_string(),
            port: 6697,
            nickname: "ironchat".to_string(),
            username: "ironchat".to_string(),
            realname: "IronChat IRCv3 Client".to_string(),
            channels: Vec::new(),
            tls_required: true,
            verify_certificates: true,
            connection_timeout: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(300),
            reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(5),
        }
    }
}

pub struct IronClient {
    config: IrcConfig,
    connection: Option<SecureConnection>,
    cap_handler: CapabilityHandler,
    sasl_auth: Option<SaslAuthenticator>,
    message_tx: Option<mpsc::UnboundedSender<IrcMessage>>,
    message_rx: Option<mpsc::UnboundedReceiver<IrcMessage>>,
    connected: bool,
    registered: bool,
    current_nick: String,
}

impl IronClient {
    pub fn new(config: IrcConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        
        Self {
            current_nick: config.nickname.clone(),
            connection: None,
            cap_handler: CapabilityHandler::new(),
            sasl_auth: None,
            message_tx: Some(tx),
            message_rx: Some(rx),
            connected: false,
            registered: false,
            config,
        }
    }

    pub fn with_sasl_plain(&mut self, username: String, password: String) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth(username, SecretString::new(password));
        self.sasl_auth = Some(auth);
        self
    }

    pub fn with_sasl_external(&mut self) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_external_auth(None);
        self.sasl_auth = Some(auth);
        self
    }

    pub fn with_sasl_scram_sha256(&mut self, username: String, password: String) -> &mut Self {
        let mut auth = SaslAuthenticator::new();
        auth.add_scram_sha256_auth(username, SecretString::new(password));
        self.sasl_auth = Some(auth);
        self
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to {}:{}", self.config.server, self.config.port);

        let connection = SecureConnection::connect(
            &self.config.server,
            self.config.port,
            self.config.verify_certificates,
        ).await?;

        self.connection = Some(connection);
        self.connected = true;

        self.perform_registration().await?;

        info!("Successfully connected and registered to {}", self.config.server);
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut conn) = self.connection.take() {
            let quit_msg = IrcMessage::new("QUIT")
                .with_params(vec!["IronChat disconnecting".to_string()]);
            
            if let Err(e) = conn.send_message(&quit_msg).await {
                warn!("Failed to send QUIT message: {}", e);
            }
            
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        self.connected = false;
        self.registered = false;
        info!("Disconnected from {}", self.config.server);
        Ok(())
    }

    pub async fn join_channel(&mut self, channel: &str) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let join_msg = IrcMessage::new("JOIN").with_params(vec![channel.to_string()]);
        self.send_message(&join_msg).await?;
        
        info!("Joining channel: {}", channel);
        Ok(())
    }

    pub async fn part_channel(&mut self, channel: &str, reason: Option<&str>) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let mut params = vec![channel.to_string()];
        if let Some(reason) = reason {
            params.push(reason.to_string());
        }

        let part_msg = IrcMessage::new("PART").with_params(params);
        self.send_message(&part_msg).await?;
        
        info!("Parting channel: {}", channel);
        Ok(())
    }

    pub async fn send_privmsg(&mut self, target: &str, message: &str) -> Result<()> {
        if !self.is_registered() {
            return Err(IronError::Connection("Not registered".to_string()));
        }

        let privmsg = IrcMessage::new("PRIVMSG")
            .with_params(vec![target.to_string(), message.to_string()]);
        
        self.send_message(&privmsg).await?;
        debug!("Sent message to {}: {}", target, message);
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        if !self.connected {
            return Err(IronError::Connection("Not connected".to_string()));
        }

        let mut ping_interval = tokio::time::interval(self.config.ping_timeout);
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            if let Err(e) = self.handle_message(message).await {
                                error!("Error handling message: {}", e);
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
                _ = ping_interval.tick() => {
                    if let Err(e) = self.send_ping().await {
                        error!("Failed to send ping: {}", e);
                        break;
                    }
                }
            }
        }

        self.connected = false;
        self.registered = false;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }

    pub fn current_nickname(&self) -> &str {
        &self.current_nick
    }

    async fn perform_registration(&mut self) -> Result<()> {
        info!("Starting IRC registration");

        self.send_raw("CAP LS 302").await?;
        
        let nick_msg = IrcMessage::new("NICK").with_params(vec![self.config.nickname.clone()]);
        self.send_message(&nick_msg).await?;

        let user_msg = IrcMessage::new("USER").with_params(vec![
            self.config.username.clone(),
            "0".to_string(), 
            "*".to_string(),
            self.config.realname.clone(),
        ]);
        self.send_message(&user_msg).await?;

        self.negotiate_capabilities().await?;

        Ok(())
    }

    async fn negotiate_capabilities(&mut self) -> Result<()> {
        let mut cap_negotiation_complete = false;
        let negotiation_timeout = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(negotiation_timeout);

        loop {
            tokio::select! {
                message_result = self.read_message() => {
                    match message_result {
                        Ok(Some(message)) => {
                            if self.handle_cap_message(&message).await? {
                                cap_negotiation_complete = true;
                                break;
                            }
                            
                            if message.command == "001" {
                                self.registered = true;
                                self.current_nick = message.params.get(0)
                                    .unwrap_or(&self.config.nickname)
                                    .clone();
                                info!("Successfully registered with nick: {}", self.current_nick);
                                break;
                            }
                        }
                        Ok(None) => {
                            return Err(IronError::Connection("Connection closed during registration".to_string()));
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                _ = &mut negotiation_timeout => {
                    warn!("Capability negotiation timeout, continuing without full capabilities");
                    break;
                }
            }
        }

        if !self.registered {
            return Err(IronError::Connection("Registration failed".to_string()));
        }

        info!("Registration complete. Current nick: {}", self.current_nick);

        for channel in &self.config.channels.clone() {
            self.join_channel(channel).await?;
        }

        Ok(())
    }

    async fn handle_cap_message(&mut self, message: &IrcMessage) -> Result<bool> {
        if message.command != "CAP" {
            return Ok(false);
        }

        if message.params.len() < 3 {
            return Ok(false);
        }

        let subcommand = &message.params[1];
        
        match subcommand.as_str() {
            "LS" => {
                let is_complete = self.cap_handler.handle_cap_ls(&message.params[1..])?;
                if is_complete {
                    let caps_to_request = self.cap_handler.get_capabilities_to_request();
                    if !caps_to_request.is_empty() {
                        let req_msg = format!("CAP REQ :{}", caps_to_request.join(" "));
                        self.send_raw(&req_msg).await?;
                    } else {
                        self.send_raw("CAP END").await?;
                        self.cap_handler.set_negotiation_complete();
                        return Ok(true);
                    }
                }
            }
            "ACK" => {
                self.cap_handler.handle_cap_ack(&message.params[2..])?;
                
                if self.cap_handler.is_capability_enabled("sasl") {
                    if let Some(ref sasl_auth) = self.sasl_auth {
                        let mechanisms = self.cap_handler.get_sasl_mechanisms();
                        if let Some(mechanism) = sasl_auth.select_mechanism(&mechanisms) {
                            warn!("SASL authentication mechanism selected: {:?}", mechanism);
                            // TODO: Implement proper SASL authentication flow
                            // For now, we'll skip authentication and continue
                        }
                    }
                }
                
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
                return Ok(false);
            }
            "NAK" => {
                self.cap_handler.handle_cap_nak(&message.params[2..])?;
                self.send_raw("CAP END").await?;
                self.cap_handler.set_negotiation_complete();
                return Ok(false);
            }
            "NEW" => {
                if message.params.len() > 2 {
                    let new_caps = self.cap_handler.handle_cap_new(&message.params[2])?;
                    if !new_caps.is_empty() {
                        let req_msg = format!("CAP REQ :{}", new_caps.join(" "));
                        self.send_raw(&req_msg).await?;
                    }
                }
            }
            "DEL" => {
                self.cap_handler.handle_cap_del(&message.params[2..])?;
            }
            _ => {}
        }

        Ok(false)
    }

    pub async fn handle_message(&mut self, message: IrcMessage) -> Result<()> {
        debug!("Handling message: {}", message.command);

        match message.command.as_str() {
            "PING" => {
                let pong_msg = IrcMessage::new("PONG")
                    .with_params(message.params);
                self.send_message(&pong_msg).await?;
                debug!("Responded to PING");
            }
            "001" => {
                self.registered = true;
                self.current_nick = message.params.get(0)
                    .unwrap_or(&self.config.nickname)
                    .clone();
                info!("Successfully registered with nick: {}", self.current_nick);
            }
            "433" | "436" => {
                warn!("Nickname {} is in use, trying alternative", self.current_nick);
                self.current_nick = format!("{}_", self.current_nick);
                let nick_msg = IrcMessage::new("NICK").with_params(vec![self.current_nick.clone()]);
                self.send_message(&nick_msg).await?;
            }
            "ERROR" => {
                let default_error = "Unknown error".to_string();
                let error_msg = message.params.get(0).unwrap_or(&default_error);
                error!("Server error: {}", error_msg);
                return Err(IronError::Connection(format!("Server error: {}", error_msg)));
            }
            _ => {
                if let Some(ref tx) = self.message_tx {
                    if let Err(_) = tx.send(message) {
                        warn!("Message channel closed");
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
        if let Some(ref mut conn) = self.connection {
            conn.send_message(message).await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    pub async fn send_raw(&mut self, data: &str) -> Result<()> {
        if let Some(ref mut conn) = self.connection {
            conn.send_raw(data).await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        if let Some(ref mut conn) = self.connection {
            conn.read_message().await
        } else {
            Err(IronError::Connection("Not connected".to_string()))
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        let ping_msg = IrcMessage::new("PING")
            .with_params(vec![self.config.server.clone()]);
        self.send_message(&ping_msg).await?;
        debug!("Sent PING to server");
        Ok(())
    }
}

impl Drop for IronClient {
    fn drop(&mut self) {
        if self.connected {
            warn!("IronClient dropped while still connected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = IrcConfig::default();
        let client = IronClient::new(config);
        
        assert!(!client.is_connected());
        assert!(!client.is_registered());
        assert_eq!(client.current_nickname(), "ironchat");
    }

    #[test]
    fn test_config_defaults() {
        let config = IrcConfig::default();
        
        assert_eq!(config.server, "irc.libera.chat");
        assert_eq!(config.port, 6697);
        assert!(config.tls_required);
        assert!(config.verify_certificates);
    }
}