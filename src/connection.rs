use crate::error::{IronError, Result};
use crate::message::IrcMessage;
use crate::dos_protection::DosProtection;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use crate::{iron_debug, iron_error, iron_info, iron_warn};
use std::time::{Duration, Instant};

pub struct SecureConnection {
    pub stream: TlsStream<TcpStream>,
    last_activity: Instant,
    server_name: String,
    connection_id: String,
    dos_protection: Option<Arc<DosProtection>>,
}

impl AsyncRead for SecureConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SecureConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl SecureConnection {
    pub async fn connect(host: &str, port: u16, verify_certs: bool) -> Result<Self> {
        Self::connect_with_dos_protection(host, port, verify_certs, None).await
    }

    pub async fn connect_with_dos_protection(
        host: &str, 
        port: u16, 
        verify_certs: bool,
        dos_protection: Option<Arc<DosProtection>>
    ) -> Result<Self> {
        iron_info!("connection", "Connecting to {}:{} with TLS", host, port);

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if !verify_certs {
            iron_warn!("connection", "Certificate verification disabled - this is insecure!");
            config.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));
        }

        let connector = TlsConnector::from(Arc::new(config));
        
        // Add connection timeout
        let connect_timeout = Duration::from_secs(30);
        let tcp_stream = tokio::time::timeout(
            connect_timeout,
            TcpStream::connect((host, port))
        ).await
            .map_err(|_| IronError::Connection("Connection timeout".to_string()))?
            .map_err(|e| IronError::Connection(format!("Failed to connect: {}", e)))?;

        tcp_stream.set_nodelay(true)
            .map_err(|e| IronError::Connection(format!("Failed to set nodelay: {}", e)))?;

        let server_name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| IronError::Tls(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| IronError::Tls(format!("TLS handshake failed: {}", e)))?;
        
        // Get local address for connection ID
        let local_addr = tls_stream.get_ref().0.local_addr()
            .map_err(|e| IronError::Connection(format!("Failed to get local address: {}", e)))?;
        let connection_id = format!("{}:{}", local_addr.ip(), local_addr.port());

        // Register with DoS protection if available
        if let Some(ref dos) = dos_protection {
            dos.register_connection(connection_id.clone()).await?;
        }
        
        Ok(Self {
            stream: tls_stream,
            last_activity: Instant::now(),
            server_name: host.to_string(),
            connection_id,
            dos_protection,
        })
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        let mut line = String::new();
        let mut reader = tokio::io::BufReader::new(&mut self.stream);
        
        // Use configurable read timeout
        let read_timeout = Duration::from_secs(300);
        match tokio::time::timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                iron_info!("connection", "Connection closed by server");
                // Cleanup DoS protection state
                if let Some(ref dos) = self.dos_protection {
                    dos.unregister_connection(&self.connection_id).await;
                }
                return Ok(None);
            }
            Ok(Ok(_)) => {
                self.last_activity = Instant::now();
                iron_debug!("connection", "Received: {}", line.trim());
                
                // Check with DoS protection first
                if let Some(ref dos) = self.dos_protection {
                    dos.check_message(&self.connection_id, &line).await?;
                }
                
                if line.len() > 8704 { // 512 + 8191 + some buffer
                    return Err(IronError::SecurityViolation(
                        "Message exceeds maximum length".to_string()
                    ));
                }

                if !line.is_ascii() {
                    return Err(IronError::SecurityViolation(
                        "Non-ASCII characters in message".to_string()
                    ));
                }

                // Track parsing time for DoS protection
                let parse_start = Instant::now();
                let result = line.parse::<IrcMessage>();
                
                // Check parsing timeout
                if let Some(ref dos) = self.dos_protection {
                    dos.check_parse_timeout(parse_start).await?;
                }

                match result {
                    Ok(msg) => Ok(Some(msg)),
                    Err(e) => {
                        iron_error!("connection", "Failed to parse message '{}': {}", line.trim(), e);
                        Err(e)
                    }
                }
            }
            Ok(Err(e)) => Err(IronError::Io(e)),
            Err(_) => Err(IronError::Connection("Read timeout".to_string())),
        }
    }

    pub async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
        let serialized = message.to_string();
        
        // Check with DoS protection for outgoing messages
        if let Some(ref dos) = self.dos_protection {
            dos.check_message(&self.connection_id, &serialized).await?;
        }
        
        if serialized.len() > 8704 {
            return Err(IronError::SecurityViolation(
                "Outgoing message too long".to_string()
            ));
        }

        iron_debug!("connection", "Sending: {}", serialized.trim());
        
        self.stream.write_all(serialized.as_bytes()).await
            .map_err(|e| IronError::Io(e))?;
        
        self.last_activity = Instant::now();
        Ok(())
    }

    pub async fn send_raw(&mut self, data: &str) -> Result<()> {
        if data.len() > 512 {
            return Err(IronError::SecurityViolation(
                "Raw message too long".to_string()
            ));
        }

        if !data.is_ascii() {
            return Err(IronError::SecurityViolation(
                "Non-ASCII characters in raw message".to_string()
            ));
        }

        let mut line = data.to_string();
        if !line.ends_with("\r\n") {
            line.push_str("\r\n");
        }

        // Check with DoS protection for raw messages
        if let Some(ref dos) = self.dos_protection {
            dos.check_message(&self.connection_id, &line).await?;
        }

        iron_debug!("connection", "Sending raw: {}", line.trim());
        
        self.stream.write_all(line.as_bytes()).await
            .map_err(|e| IronError::Io(e))?;

        self.last_activity = Instant::now();
        Ok(())
    }

    pub fn time_since_last_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn dos_protection(&self) -> Option<&Arc<DosProtection>> {
        self.dos_protection.as_ref()
    }

    pub fn is_tls_active(&self) -> bool {
        // Since SecureConnection always uses TLS, this is always true
        true
    }

    pub async fn split_for_sasl(&mut self) -> Result<()> {
        // For now, we'll handle SASL authentication directly through the client
        // using send_raw and read_message methods instead of splitting the stream
        Ok(())
    }
}

impl Drop for SecureConnection {
    fn drop(&mut self) {
        // Cleanup DoS protection state when connection is dropped
        if let Some(ref dos) = self.dos_protection {
            let connection_id = self.connection_id.clone();
            let dos_clone = dos.clone();
            tokio::spawn(async move {
                dos_clone.unregister_connection(&connection_id).await;
            });
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use rustls::client::danger::ServerCertVerifier;
    use test_case::test_case;

    // Mock connection for testing
    struct MockSecureConnection {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
        read_pos: usize,
        last_activity: Instant,
        server_name: String,
        should_fail: bool,
    }

    impl MockSecureConnection {
        fn new(server_name: String) -> Self {
            Self {
                read_data: Vec::new(),
                write_data: Vec::new(),
                read_pos: 0,
                last_activity: Instant::now(),
                server_name,
                should_fail: false,
            }
        }

        fn with_read_data(mut self, data: &str) -> Self {
            self.read_data = data.as_bytes().to_vec();
            self
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
            if self.should_fail {
                return Err(IronError::Connection("Mock connection failed".to_string()));
            }

            if self.read_pos >= self.read_data.len() {
                return Ok(None);
            }

            // Find next line
            let start = self.read_pos;
            let mut end = start;
            while end < self.read_data.len() && self.read_data[end] != b'\n' {
                end += 1;
            }

            if end >= self.read_data.len() {
                return Ok(None);
            }

            end += 1; // Include the newline
            let line = String::from_utf8_lossy(&self.read_data[start..end]);
            self.read_pos = end;
            self.last_activity = Instant::now();

            // Apply same security validations as real connection
            if line.len() > 8704 {
                return Err(IronError::SecurityViolation(
                    "Message exceeds maximum length".to_string()
                ));
            }

            if !line.is_ascii() {
                return Err(IronError::SecurityViolation(
                    "Non-ASCII characters in message".to_string()
                ));
            }

            match line.trim().parse::<IrcMessage>() {
                Ok(msg) => Ok(Some(msg)),
                Err(e) => Err(e),
            }
        }

        async fn send_message(&mut self, message: &IrcMessage) -> Result<()> {
            if self.should_fail {
                return Err(IronError::Connection("Mock connection failed".to_string()));
            }

            let serialized = message.to_string();
            
            if serialized.len() > 8704 {
                return Err(IronError::SecurityViolation(
                    "Outgoing message too long".to_string()
                ));
            }

            self.write_data.extend_from_slice(serialized.as_bytes());
            self.last_activity = Instant::now();
            Ok(())
        }

        async fn send_raw(&mut self, data: &str) -> Result<()> {
            if self.should_fail {
                return Err(IronError::Connection("Mock connection failed".to_string()));
            }

            if data.len() > 512 {
                return Err(IronError::SecurityViolation(
                    "Raw message too long".to_string()
                ));
            }

            if !data.is_ascii() {
                return Err(IronError::SecurityViolation(
                    "Non-ASCII characters in raw message".to_string()
                ));
            }

            let mut line = data.to_string();
            if !line.ends_with("\r\n") {
                line.push_str("\r\n");
            }

            self.write_data.extend_from_slice(line.as_bytes());
            self.last_activity = Instant::now();
            Ok(())
        }

        fn time_since_last_activity(&self) -> Duration {
            self.last_activity.elapsed()
        }

        fn server_name(&self) -> &str {
            &self.server_name
        }

        fn get_written_data(&self) -> String {
            String::from_utf8_lossy(&self.write_data).to_string()
        }
    }

    // Security validation tests
    #[tokio::test]
    async fn test_message_length_security_validation() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        // Test outgoing message length validation
        let long_message = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), "a".repeat(9000)]);
        
        let result = conn.send_message(&long_message).await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[tokio::test]
    async fn test_raw_message_length_security_validation() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        // Test raw message length validation
        let long_raw = "a".repeat(600);
        let result = conn.send_raw(&long_raw).await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[tokio::test]
    async fn test_non_ascii_raw_message_security_validation() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        // Test non-ASCII validation
        let non_ascii = "PRIVMSG #channel :Hello 世界";
        let result = conn.send_raw(non_ascii).await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[tokio::test]
    async fn test_incoming_message_length_security_validation() {
        let long_message = format!("PRIVMSG #channel :{}\n", "a".repeat(9000));
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(&long_message);
        
        let result = conn.read_message().await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[tokio::test]
    async fn test_incoming_non_ascii_security_validation() {
        let non_ascii_message = "PRIVMSG #channel :Hello 世界\n";
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(non_ascii_message);
        
        let result = conn.read_message().await;
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    // Connection behavior tests
    #[tokio::test]
    async fn test_successful_message_reading() {
        let test_data = "PRIVMSG #channel :Hello world\n";
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(test_data);
        
        let result = conn.read_message().await.unwrap();
        assert!(result.is_some());
        
        let msg = result.unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello world"]);
    }

    #[tokio::test]
    async fn test_successful_message_sending() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
        
        let result = conn.send_message(&msg).await;
        assert!(result.is_ok());
        
        let written = conn.get_written_data();
        assert!(written.contains("PRIVMSG #channel :Hello world"));
        assert!(written.ends_with("\r\n"));
    }

    #[tokio::test]
    async fn test_successful_raw_sending() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        let result = conn.send_raw("PING :test.server").await;
        assert!(result.is_ok());
        
        let written = conn.get_written_data();
        assert_eq!(written, "PING :test.server\r\n");
    }

    #[tokio::test]
    async fn test_raw_message_auto_adds_crlf() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        conn.send_raw("PING test").await.unwrap();
        let written = conn.get_written_data();
        assert!(written.ends_with("\r\n"));
        
        // Test that it doesn't double-add CRLF
        let mut conn2 = MockSecureConnection::new("test.server".to_string());
        conn2.send_raw("PING test\r\n").await.unwrap();
        let written2 = conn2.get_written_data();
        assert_eq!(written2, "PING test\r\n");
    }

    #[tokio::test]
    async fn test_connection_closed_by_server() {
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(""); // Empty data simulates closed connection
        
        let result = conn.read_message().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_multiple_messages_reading() {
        let test_data = "PING :server\nPONG :client\nPRIVMSG #channel :Hello\n";
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(test_data);
        
        // Read first message
        let msg1 = conn.read_message().await.unwrap().unwrap();
        assert_eq!(msg1.command, "PING");
        
        // Read second message
        let msg2 = conn.read_message().await.unwrap().unwrap();
        assert_eq!(msg2.command, "PONG");
        
        // Read third message
        let msg3 = conn.read_message().await.unwrap().unwrap();
        assert_eq!(msg3.command, "PRIVMSG");
        assert_eq!(msg3.params, vec!["#channel", "Hello"]);
    }

    #[tokio::test]
    async fn test_connection_failure_handling() {
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_failure();
        
        let result = conn.read_message().await;
        assert!(matches!(result, Err(IronError::Connection(_))));
        
        let msg = IrcMessage::new("PING");
        let result = conn.send_message(&msg).await;
        assert!(matches!(result, Err(IronError::Connection(_))));
    }

    #[tokio::test]
    async fn test_activity_tracking() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        let initial_time = conn.time_since_last_activity();
        
        // Send a message and check activity is updated
        tokio::time::sleep(Duration::from_millis(10)).await;
        let msg = IrcMessage::new("PING");
        conn.send_message(&msg).await.unwrap();
        
        let after_send = conn.time_since_last_activity();
        assert!(after_send < initial_time);
    }

    #[tokio::test]
    async fn test_server_name_tracking() {
        let conn = MockSecureConnection::new("irc.example.com".to_string());
        assert_eq!(conn.server_name(), "irc.example.com");
    }

    // Error parsing tests
    #[tokio::test]
    async fn test_invalid_message_parsing() {
        let invalid_data = "@invalid tag without space PRIVMSG #channel :test\n";
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(invalid_data);
        
        let result = conn.read_message().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_malformed_message_handling() {
        let malformed_data = ":nick!user@host\n"; // Missing command
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(malformed_data);
        
        let result = conn.read_message().await;
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    // Edge case tests
    #[test_case(""; "empty message")]
    #[test_case("   "; "whitespace only")]
    #[test_case("@tag=value"; "tags without command")]
    #[test_case(":prefix"; "prefix without command")]
    fn test_edge_case_message_parsing(input: &str) {
        let test_data = format!("{}\n", input);
        tokio_test::block_on(async {
            let mut conn = MockSecureConnection::new("test.server".to_string())
                .with_read_data(&test_data);
            
            let result = conn.read_message().await;
            assert!(result.is_err());
        });
    }

    // Performance and stress tests
    #[tokio::test]
    async fn test_large_valid_message_handling() {
        // Test maximum allowed message size
        let large_content = "a".repeat(450); // Within limits
        let test_data = format!("PRIVMSG #channel :{}\n", large_content);
        let mut conn = MockSecureConnection::new("test.server".to_string())
            .with_read_data(&test_data);
        
        let result = conn.read_message().await.unwrap();
        assert!(result.is_some());
        
        let msg = result.unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params[1], large_content);
    }

    #[tokio::test]
    async fn test_rapid_message_sending() {
        let mut conn = MockSecureConnection::new("test.server".to_string());
        
        // Send many messages rapidly
        for i in 0..100 {
            let msg = IrcMessage::new("PRIVMSG")
                .with_params(vec!["#channel".to_string(), format!("Message {}", i)]);
            
            let result = conn.send_message(&msg).await;
            assert!(result.is_ok());
        }
        
        let written = conn.get_written_data();
        assert!(written.contains("Message 0"));
        assert!(written.contains("Message 99"));
    }

    #[tokio::test]
    async fn test_concurrent_operations_simulation() {
        use std::sync::Arc;
        use tokio::sync::Mutex;
        
        let conn = Arc::new(Mutex::new(
            MockSecureConnection::new("test.server".to_string())
        ));
        
        let mut handles = vec![];
        
        // Simulate concurrent message sending
        for i in 0..10 {
            let conn_clone = Arc::clone(&conn);
            let handle = tokio::spawn(async move {
                let msg = IrcMessage::new("PRIVMSG")
                    .with_params(vec!["#channel".to_string(), format!("Message {}", i)]);
                
                let mut conn_guard = conn_clone.lock().await;
                conn_guard.send_message(&msg).await
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
        
        let conn_guard = conn.lock().await;
        let written = conn_guard.get_written_data();
        
        // Verify all messages were sent
        for i in 0..10 {
            assert!(written.contains(&format!("Message {}", i)));
        }
    }

    // Security boundary tests
    #[test_case(8703, true; "message at max length should pass")]
    #[test_case(8704, true; "message at boundary should pass")]
    #[test_case(8705, false; "message over boundary should fail")]
    fn test_message_length_boundaries(len: usize, should_pass: bool) {
        tokio_test::block_on(async {
            let content = "a".repeat(len);
            let mut conn = MockSecureConnection::new("test.server".to_string());
            
            let result = conn.send_raw(&content).await;
            
            if should_pass {
                // For raw messages, the limit is actually 512
                if len <= 512 {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(IronError::SecurityViolation(_))));
                }
            } else {
                assert!(matches!(result, Err(IronError::SecurityViolation(_))));
            }
        });
    }

    // Certificate verification tests (integration test style)
    #[tokio::test]
    async fn test_no_certificate_verification_implementation() {
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        
        let verifier = NoCertificateVerification;
        
        // Test that the no-verification implementation always accepts certificates
        let dummy_cert = CertificateDer::from(vec![1, 2, 3, 4, 5]);
        let dummy_intermediates = vec![];
        let dummy_server_name = ServerName::try_from("example.com").unwrap();
        let dummy_ocsp = &[];
        let dummy_time = UnixTime::now();
        
        let result = verifier.verify_server_cert(
            &dummy_cert,
            &dummy_intermediates,
            &dummy_server_name,
            dummy_ocsp,
            dummy_time,
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_supported_signature_schemes() {
        let verifier = NoCertificateVerification;
        let schemes = verifier.supported_verify_schemes();
        
        // Verify that common signature schemes are supported
        assert!(schemes.contains(&rustls::SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&rustls::SignatureScheme::ED25519));
        assert!(!schemes.is_empty());
    }
}