use crate::error::{IronError, Result};
use secrecy::{ExposeSecret, SecretString};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncWrite, AsyncBufRead, AsyncWriteExt, AsyncBufReadExt};
use std::time::Duration;
use crate::{iron_debug, iron_info, iron_warn, iron_error};

#[derive(Debug, Clone)]
pub enum SaslMechanism {
    Plain { username: String, password: SecretString, authzid: Option<String> },
    External { authzid: Option<String> },
    ScramSha256 { username: String, password: SecretString },
}

pub struct SaslAuthenticator {
    mechanisms: Vec<SaslMechanism>,
    timeout: Duration,
}

impl SaslAuthenticator {
    pub fn new() -> Self {
        Self {
            mechanisms: Vec::new(),
            timeout: Duration::from_secs(30),
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
        iron_info!("auth", "Starting PLAIN authentication for user: {}", username);

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
        iron_info!("auth", "Starting EXTERNAL authentication");

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
        iron_warn!("auth", "SCRAM-SHA-256 not yet implemented, falling back to simpler mechanism");
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
                iron_debug!("auth", "Received authenticate response: {}", line);
                
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
                
                iron_debug!("auth", "Received response: {}", line);

                if let Some(numeric) = Self::parse_numeric_response(line) {
                    match numeric {
                        900 | 903 => {
                            iron_info!("auth", "SASL authentication successful");
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
                iron_error!("auth", "SASL authentication failed: {}", e);
                Err(IronError::Auth(format!("Authentication failed: {}", e)))
            }
            Err(_) => {
                iron_error!("auth", "SASL authentication timeout");
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
    use tokio::io::{AsyncBufRead, AsyncWrite};
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use test_case::test_case;
    use proptest::prelude::*;

    // Mock writer for testing
    struct MockWriter {
        data: Vec<u8>,
        should_fail: bool,
    }

    impl MockWriter {
        fn new() -> Self {
            Self {
                data: Vec::new(),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                data: Vec::new(),
                should_fail: true,
            }
        }

        fn get_written_data(&self) -> String {
            String::from_utf8_lossy(&self.data).to_string()
        }
    }

    impl AsyncWrite for MockWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::result::Result<usize, std::io::Error>> {
            if self.should_fail {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Mock write failure",
                )));
            }
            self.data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    // Mock reader for testing
    struct MockReader {
        data: Cursor<Vec<u8>>,
        should_fail: bool,
    }

    impl MockReader {
        fn new(data: &str) -> Self {
            Self {
                data: Cursor::new(data.as_bytes().to_vec()),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                data: Cursor::new(Vec::new()),
                should_fail: true,
            }
        }
    }

    impl AsyncBufRead for MockReader {
        fn poll_fill_buf(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<&[u8]>> {
            if self.should_fail {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Mock read failure",
                )));
            }
            let this = self.get_mut();
            Pin::new(&mut this.data).poll_fill_buf(cx)
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            Pin::new(&mut this.data).consume(amt)
        }
    }

    impl tokio::io::AsyncRead for MockReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.data).poll_read(cx, buf)
        }
    }

    // Basic functionality tests
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
    fn test_chunk_response_empty() {
        let chunks = SaslAuthenticator::chunk_response("");
        assert_eq!(chunks, vec!["+"]);
    }

    #[test]
    fn test_chunk_response_exactly_400_chars() {
        let response = "a".repeat(400);
        let chunks = SaslAuthenticator::chunk_response(&response);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1], "+");
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
    fn test_mechanism_selection_preference_order() {
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth("user".to_string(), SecretString::new("pass".to_string()));
        auth.add_external_auth(None);
        auth.add_scram_sha256_auth("user".to_string(), SecretString::new("pass".to_string()));

        // Test preference order: EXTERNAL > SCRAM-SHA-256 > PLAIN
        let server_mechs = vec!["PLAIN".to_string(), "SCRAM-SHA-256".to_string(), "EXTERNAL".to_string()];
        let selected = auth.select_mechanism(&server_mechs);
        assert!(matches!(selected, Some(SaslMechanism::External { .. })));

        let server_mechs = vec!["PLAIN".to_string(), "SCRAM-SHA-256".to_string()];
        let selected = auth.select_mechanism(&server_mechs);
        assert!(matches!(selected, Some(SaslMechanism::ScramSha256 { .. })));

        let server_mechs = vec!["PLAIN".to_string()];
        let selected = auth.select_mechanism(&server_mechs);
        assert!(matches!(selected, Some(SaslMechanism::Plain { .. })));
    }

    #[test]
    fn test_mechanism_selection_no_match() {
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth("user".to_string(), SecretString::new("pass".to_string()));

        let server_mechs = vec!["EXTERNAL".to_string(), "SCRAM-SHA-256".to_string()];
        let selected = auth.select_mechanism(&server_mechs);
        assert!(selected.is_none());
    }

    #[test]
    fn test_parse_numeric() {
        assert_eq!(SaslAuthenticator::parse_numeric_response(":server 903 nick :Success"), Some(903));
        assert_eq!(SaslAuthenticator::parse_numeric_response(":server 904 nick :Failed"), Some(904));
        assert_eq!(SaslAuthenticator::parse_numeric_response("invalid"), None);
        assert_eq!(SaslAuthenticator::parse_numeric_response("PRIVMSG #channel :test"), None);
        assert_eq!(SaslAuthenticator::parse_numeric_response(""), None);
        assert_eq!(SaslAuthenticator::parse_numeric_response(":server abc nick :Invalid"), None);
    }

    // PLAIN authentication tests
    #[tokio::test]
    async fn test_plain_auth_success() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let auth = SaslAuthenticator::new();

        let result = auth.authenticate_plain(&mut writer, &mut reader, "testuser", &SecretString::new("testpass".to_string()), None).await;
        assert!(result.is_ok());

        let written = writer.get_written_data();
        assert!(written.contains("AUTHENTICATE PLAIN\r\n"));
        assert!(written.contains("AUTHENTICATE "));
    }

    #[tokio::test]
    async fn test_plain_auth_with_authzid() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "testuser", &SecretString::new("testpass".to_string()), Some("authz")).await;
        assert!(result.is_ok());

        let written = writer.get_written_data();
        assert!(written.contains("AUTHENTICATE PLAIN\r\n"));
    }

    #[tokio::test]
    async fn test_plain_auth_failure() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 904 nick :Authentication failed\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "testuser", &SecretString::new("wrongpass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    #[tokio::test]
    async fn test_plain_auth_unexpected_response() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE INVALID\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "testuser", &SecretString::new("testpass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    #[tokio::test]
    async fn test_plain_auth_without_tls() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("");
        
        let auth = SaslAuthenticator::new();
        let mechanism = SaslMechanism::Plain {
            username: "testuser".to_string(),
            password: SecretString::new("testpass".to_string()),
            authzid: None,
        };

        let result = auth.authenticate(&mut writer, &mut reader, &mechanism, false).await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    // EXTERNAL authentication tests
    #[tokio::test]
    async fn test_external_auth_success() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_external(&mut writer, &mut reader, None).await;
        assert!(result.is_ok());

        let written = writer.get_written_data();
        assert!(written.contains("AUTHENTICATE EXTERNAL\r\n"));
        assert!(written.contains("AUTHENTICATE +\r\n"));
    }

    #[tokio::test]
    async fn test_external_auth_with_authzid() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_external(&mut writer, &mut reader, Some("authz")).await;
        assert!(result.is_ok());

        let written = writer.get_written_data();
        assert!(written.contains("AUTHENTICATE EXTERNAL\r\n"));
        // Should contain base64-encoded authzid
        assert!(written.contains("AUTHENTICATE "));
    }

    #[tokio::test]
    async fn test_external_auth_failure() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 904 nick :Authentication failed\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_external(&mut writer, &mut reader, None).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    // SCRAM-SHA-256 tests (currently unimplemented)
    #[tokio::test]
    async fn test_scram_sha256_not_implemented() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_scram_sha256(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string())).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    // Error response code tests
    #[test_case("902", "Account unavailable")]
    #[test_case("904", "Authentication failed")]
    #[test_case("905", "Message too long")]
    #[test_case("906", "Authentication aborted")]
    #[test_case("907", "Already authenticated")]
    fn test_sasl_error_codes(code: &str, expected_desc: &str) {
        tokio_test::block_on(async {
            let mut writer = MockWriter::new();
            let response = format!("AUTHENTICATE +\n:server {} nick :{}\n", code, expected_desc);
            let mut reader = MockReader::new(&response);
            
            let auth = SaslAuthenticator::new();
            let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
            
            assert!(matches!(result, Err(IronError::Auth(_))));
        });
    }

    // Success response tests  
    #[test_case("900")]
    #[test_case("903")]
    fn test_sasl_success_codes(code: &str) {
        tokio_test::block_on(async {
            let mut writer = MockWriter::new();
            let response = format!("AUTHENTICATE +\n:server {} nick :Success\n", code);
            let mut reader = MockReader::new(&response);
            
            let auth = SaslAuthenticator::new();
            let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
            
            assert!(result.is_ok());
        });
    }

    // Timeout tests
    #[tokio::test]
    async fn test_auth_timeout() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n"); // No final response
        
        let mut auth = SaslAuthenticator::new();
        auth.timeout = Duration::from_millis(100); // Very short timeout
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    // I/O error tests
    #[tokio::test]
    async fn test_write_failure() {
        let mut writer = MockWriter::with_failure();
        let mut reader = MockReader::new("");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Io(_))));
    }

    #[tokio::test]
    async fn test_read_failure() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::with_failure();
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Io(_))));
    }

    // SecureCredentials tests
    #[test]
    fn test_secure_credentials_creation() {
        let creds = SecureCredentials::new("testuser".to_string(), "testpass".to_string());
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password.expose_secret(), "testpass");
        assert!(creds.realm.is_none());
    }

    #[test]
    fn test_secure_credentials_from_env() {
        std::env::set_var("TEST_USERNAME", "envuser");
        std::env::set_var("TEST_PASSWORD", "envpass");
        
        let result = SecureCredentials::from_env("TEST_USERNAME", "TEST_PASSWORD");
        assert!(result.is_ok());
        
        let creds = result.unwrap();
        assert_eq!(creds.username, "envuser");
        assert_eq!(creds.password.expose_secret(), "envpass");
        
        std::env::remove_var("TEST_USERNAME");
        std::env::remove_var("TEST_PASSWORD");
    }

    #[test]
    fn test_secure_credentials_from_env_missing() {
        let result = SecureCredentials::from_env("NONEXISTENT_USER", "NONEXISTENT_PASS");
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    #[test]
    fn test_secure_credentials_from_env_empty() {
        std::env::set_var("EMPTY_USERNAME", "");
        std::env::set_var("EMPTY_PASSWORD", "pass");
        
        let result = SecureCredentials::from_env("EMPTY_USERNAME", "EMPTY_PASSWORD");
        assert!(matches!(result, Err(IronError::Auth(_))));
        
        std::env::remove_var("EMPTY_USERNAME");
        std::env::remove_var("EMPTY_PASSWORD");
    }

    #[test]
    fn test_secure_credentials_from_env_too_long() {
        let long_username = "a".repeat(300);
        let long_password = "b".repeat(1500);
        
        std::env::set_var("LONG_USERNAME", &long_username);
        std::env::set_var("LONG_PASSWORD", &long_password);
        
        let result = SecureCredentials::from_env("LONG_USERNAME", "LONG_PASSWORD");
        assert!(matches!(result, Err(IronError::Auth(_))));
        
        std::env::remove_var("LONG_USERNAME");
        std::env::remove_var("LONG_PASSWORD");
    }

    // Integration tests
    #[tokio::test]
    async fn test_full_authentication_flow_plain() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let mut auth = SaslAuthenticator::new();
        auth.add_plain_auth("testuser".to_string(), SecretString::new("testpass".to_string()));
        
        let server_mechanisms = vec!["PLAIN".to_string()];
        let selected = auth.select_mechanism(&server_mechanisms).unwrap();
        
        let result = auth.authenticate(&mut writer, &mut reader, selected, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_full_authentication_flow_external() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Authentication successful\n");
        
        let mut auth = SaslAuthenticator::new();
        auth.add_external_auth(Some("authzid".to_string()));
        
        let server_mechanisms = vec!["EXTERNAL".to_string()];
        let selected = auth.select_mechanism(&server_mechanisms).unwrap();
        
        let result = auth.authenticate(&mut writer, &mut reader, selected, true).await;
        assert!(result.is_ok());
    }

    // Edge case and security tests
    #[tokio::test]
    async fn test_malformed_authenticate_response() {
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("INVALID RESPONSE\n");
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    #[tokio::test]
    async fn test_multiple_sasl_responses() {
        let mut writer = MockWriter::new();
        let responses = [
            "AUTHENTICATE +\n",
            ":server 900 nick :Logging in\n",
            ":server 903 nick :Authentication successful\n"
        ].join("");
        let mut reader = MockReader::new(&responses);
        
        let auth = SaslAuthenticator::new();
        
        let result = auth.authenticate_plain(&mut writer, &mut reader, "user", &SecretString::new("pass".to_string()), None).await;
        assert!(result.is_ok());
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_chunk_response_properties(
            input in ".*"
        ) {
            let chunks = SaslAuthenticator::chunk_response(&input);
            
            // All chunks should be <= 400 characters
            prop_assert!(chunks.iter().all(|chunk| chunk.len() <= 400));
            
            // Should have at least one chunk
            prop_assert!(!chunks.is_empty());
            
            // If input is empty, should return ["+"]
            if input.is_empty() {
                prop_assert_eq!(chunks, vec!["+"]);
            }
        }

        #[test]
        fn test_credentials_validation(
            username in "[a-zA-Z0-9_]{1,255}",
            password in "[a-zA-Z0-9!@#$%^&*()_+]{1,1024}"
        ) {
            let creds = SecureCredentials::new(username.clone(), password.clone());
            prop_assert_eq!(creds.username.clone(), username);
            prop_assert_eq!(creds.password.expose_secret(), &password);
        }
    }

    // Stress tests
    #[tokio::test]
    async fn test_large_credential_handling() {
        let large_username = "a".repeat(200);
        let large_password = "b".repeat(500);
        
        let creds = SecureCredentials::new(large_username.clone(), large_password.clone());
        assert_eq!(creds.username, large_username);
        assert_eq!(creds.password.expose_secret(), &large_password);
    }

    #[tokio::test]
    async fn test_special_characters_in_credentials() {
        let special_username = "user@example.com";
        let special_password = "p@ssw0rd!#$%";
        
        let mut writer = MockWriter::new();
        let mut reader = MockReader::new("AUTHENTICATE +\n:server 903 nick :Success\n");
        
        let auth = SaslAuthenticator::new();
        let result = auth.authenticate_plain(&mut writer, &mut reader, special_username, &SecretString::new(special_password.to_string()), None).await;
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_mechanism_cloning() {
        let plain_mech = SaslMechanism::Plain {
            username: "user".to_string(),
            password: SecretString::new("pass".to_string()),
            authzid: None,
        };
        
        let cloned = plain_mech.clone();
        assert!(matches!(cloned, SaslMechanism::Plain { .. }));
    }

    #[test]
    fn test_mechanism_debug() {
        let external_mech = SaslMechanism::External { authzid: None };
        let debug_str = format!("{:?}", external_mech);
        assert!(debug_str.contains("External"));
    }
}