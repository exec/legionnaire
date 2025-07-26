use crate::error::{IronError, Result};
use secrecy::{ExposeSecret, SecretString};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncWrite, AsyncBufRead, AsyncWriteExt, AsyncBufReadExt};
use std::time::Duration;
use tracing::{debug, info, warn, error};

#[derive(Debug, Clone)]
pub enum SaslMechanism {
    Plain { username: String, password: SecretString, authzid: Option<String> },
    External { authzid: Option<String> },
    ScramSha256 { username: String, password: SecretString },
}

pub struct SaslAuthenticator {
    mechanisms: Vec<SaslMechanism>,
    timeout: Duration,
    max_retries: usize,
}

impl SaslAuthenticator {
    pub fn new() -> Self {
        Self {
            mechanisms: Vec::new(),
            timeout: Duration::from_secs(30),
            max_retries: 2,
        }
    }

    pub fn add_plain_auth(&mut self, username: String, password: SecretString) {
        self.mechanisms.push(SaslMechanism::Plain {
            username,
            password,
            authzid: None,
        });
    }

    pub fn add_external_auth(&mut self, authzid: Option<String>) {
        self.mechanisms.push(SaslMechanism::External { authzid });
    }

    pub fn add_scram_sha256_auth(&mut self, username: String, password: SecretString) {
        self.mechanisms.push(SaslMechanism::ScramSha256 { username, password });
    }

    pub fn select_mechanism(&self, server_mechanisms: &[String]) -> Option<&SaslMechanism> {
        let preference_order = ["EXTERNAL", "SCRAM-SHA-256", "PLAIN"];
        
        for preferred in &preference_order {
            if server_mechanisms.iter().any(|m| m.trim() == *preferred) {
                return self.mechanisms.iter().find(|mech| {
                    match mech {
                        SaslMechanism::External { .. } => *preferred == "EXTERNAL",
                        SaslMechanism::ScramSha256 { .. } => *preferred == "SCRAM-SHA-256",
                        SaslMechanism::Plain { .. } => *preferred == "PLAIN",
                    }
                });
            }
        }
        
        None
    }

    pub async fn authenticate<W, R>(
        &self,
        writer: &mut W,
        reader: &mut R,
        mechanism: &SaslMechanism,
        tls_active: bool,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncBufRead + Unpin,
    {
        if matches!(mechanism, SaslMechanism::Plain { .. }) && !tls_active {
            return Err(IronError::SecurityViolation(
                "PLAIN authentication requires TLS".to_string()
            ));
        }

        match mechanism {
            SaslMechanism::Plain { username, password, authzid } => {
                self.authenticate_plain(writer, reader, username, password, authzid.as_deref()).await
            }
            SaslMechanism::External { authzid } => {
                self.authenticate_external(writer, reader, authzid.as_deref()).await
            }
            SaslMechanism::ScramSha256 { username, password } => {
                self.authenticate_scram_sha256(writer, reader, username, password).await
            }
        }
    }

    async fn authenticate_plain<W, R>(
        &self,
        writer: &mut W,
        reader: &mut R,
        username: &str,
        password: &SecretString,
        authzid: Option<&str>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncBufRead + Unpin,
    {
        info!("Starting PLAIN authentication for user: {}", username);

        writer.write_all(b"AUTHENTICATE PLAIN\r\n").await
            .map_err(|e| IronError::Io(e))?;

        let server_response = self.read_authenticate_response(reader).await?;
        if server_response != "+" {
            return Err(IronError::Auth(
                format!("Unexpected server response: {}", server_response)
            ));
        }

        let authz = authzid.unwrap_or("");
        let response = format!("{}\0{}\0{}", authz, username, password.expose_secret());
        
        let chunks = Self::chunk_response(&response);
        for chunk in chunks {
            let command = format!("AUTHENTICATE {}\r\n", chunk);
            writer.write_all(command.as_bytes()).await
                .map_err(|e| IronError::Io(e))?;
        }

        self.wait_for_auth_success(reader).await
    }

    async fn authenticate_external<W, R>(
        &self,
        writer: &mut W,
        reader: &mut R,
        authzid: Option<&str>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncBufRead + Unpin,
    {
        info!("Starting EXTERNAL authentication");

        writer.write_all(b"AUTHENTICATE EXTERNAL\r\n").await
            .map_err(|e| IronError::Io(e))?;

        let server_response = self.read_authenticate_response(reader).await?;
        if server_response != "+" {
            return Err(IronError::Auth(
                format!("Unexpected server response: {}", server_response)
            ));
        }

        let response = match authzid {
            Some(authz) => BASE64.encode(authz.as_bytes()),
            None => "+".to_string(),
        };

        let command = format!("AUTHENTICATE {}\r\n", response);
        writer.write_all(command.as_bytes()).await
            .map_err(|e| IronError::Io(e))?;

        self.wait_for_auth_success(reader).await
    }

    async fn authenticate_scram_sha256<W, R>(
        &self,
        _writer: &mut W,
        _reader: &mut R,
        _username: &str,
        _password: &SecretString,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncBufRead + Unpin,
    {
        warn!("SCRAM-SHA-256 not yet implemented, falling back to simpler mechanism");
        Err(IronError::Auth("SCRAM-SHA-256 not implemented".to_string()))
    }

    async fn read_authenticate_response<R>(&self, reader: &mut R) -> Result<String>
    where
        R: AsyncBufRead + Unpin,
    {
        let timeout_result = tokio::time::timeout(self.timeout, async {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            Ok::<String, std::io::Error>(line.trim().to_string())
        }).await;

        match timeout_result {
            Ok(Ok(line)) => {
                debug!("Received authenticate response: {}", line);
                
                if line.starts_with("AUTHENTICATE ") {
                    let response = &line[13..];
                    Ok(response.to_string())
                } else {
                    Err(IronError::Auth(
                        format!("Invalid authenticate response: {}", line)
                    ))
                }
            }
            Ok(Err(e)) => Err(IronError::Io(e)),
            Err(_) => Err(IronError::Auth("Authentication timeout".to_string())),
        }
    }

    async fn wait_for_auth_success<R>(&self, reader: &mut R) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
    {
        let timeout_result = tokio::time::timeout(self.timeout, async {
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let line = line.trim();
                
                debug!("Received response: {}", line);

                if let Some(numeric) = Self::parse_numeric_response(line) {
                    match numeric {
                        900 | 903 => {
                            info!("SASL authentication successful");
                            return Ok(());
                        }
                        902 => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "Account unavailable"
                            ));
                        }
                        904 => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "Authentication failed"
                            ));
                        }
                        905 => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Message too long"
                            ));
                        }
                        906 => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Authentication aborted"
                            ));
                        }
                        907 => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "Already authenticated"
                            ));
                        }
                        _ => continue,
                    }
                }
            }
        }).await;

        match timeout_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                error!("SASL authentication failed: {}", e);
                Err(IronError::Auth(format!("Authentication failed: {}", e)))
            }
            Err(_) => {
                error!("SASL authentication timeout");
                Err(IronError::Auth("Authentication timeout".to_string()))
            }
        }
    }

    fn chunk_response(response: &str) -> Vec<String> {
        if response.is_empty() {
            return vec!["+".to_string()];
        }
        
        let encoded = BASE64.encode(response.as_bytes());
        let mut chunks = Vec::new();
        
        for chunk in encoded.as_bytes().chunks(400) {
            chunks.push(String::from_utf8(chunk.to_vec()).unwrap());
        }
        
        if encoded.len() % 400 == 0 && !encoded.is_empty() {
            chunks.push("+".to_string());
        }
        
        chunks
    }

    fn parse_numeric_response(line: &str) -> Option<u16> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1].parse().ok()
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct SecureCredentials {
    pub username: String,
    pub password: SecretString,
    pub realm: Option<String>,
}

impl SecureCredentials {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password: SecretString::new(password),
            realm: None,
        }
    }
    
    pub fn from_env(username_var: &str, password_var: &str) -> Result<Self> {
        let username = std::env::var(username_var)
            .map_err(|_| IronError::Auth("Missing username environment variable".to_string()))?;
        let password = std::env::var(password_var)
            .map_err(|_| IronError::Auth("Missing password environment variable".to_string()))?;
        
        if username.is_empty() || password.is_empty() {
            return Err(IronError::Auth("Empty credentials".to_string()));
        }
        
        if username.len() > 255 || password.len() > 1024 {
            return Err(IronError::Auth("Credentials too long".to_string()));
        }
        
        Ok(Self::new(username, password))
    }
}

impl Drop for SecureCredentials {
    fn drop(&mut self) {
        use secrecy::Zeroize;
        self.username.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_response() {
        let short_response = "test";
        let chunks = SaslAuthenticator::chunk_response(short_response);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].len() <= 400);

        let long_response = "a".repeat(600);
        let chunks = SaslAuthenticator::chunk_response(&long_response);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 400));
    }

    #[test]
    fn test_mechanism_selection() {
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth("user".to_string(), SecretString::new("pass".to_string()));
        auth.add_external_auth(None);

        let server_mechs = vec!["PLAIN".to_string(), "EXTERNAL".to_string()];
        let selected = auth.select_mechanism(&server_mechs);
        
        assert!(matches!(selected, Some(SaslMechanism::External { .. })));
    }

    #[test]
    fn test_parse_numeric() {
        assert_eq!(SaslAuthenticator::parse_numeric_response(":server 903 nick :Success"), Some(903));
        assert_eq!(SaslAuthenticator::parse_numeric_response(":server 904 nick :Failed"), Some(904));
        assert_eq!(SaslAuthenticator::parse_numeric_response("invalid"), None);
    }
}