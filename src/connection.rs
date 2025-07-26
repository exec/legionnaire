use crate::error::{IronError, Result};
use crate::message::IrcMessage;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tracing::{debug, error, info, warn};
use std::time::{Duration, Instant};

pub struct SecureConnection {
    pub stream: TlsStream<TcpStream>,
    last_activity: Instant,
    server_name: String,
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
        info!("Connecting to {}:{} with TLS", host, port);

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if !verify_certs {
            warn!("Certificate verification disabled - this is insecure!");
            config.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));
        }

        let connector = TlsConnector::from(Arc::new(config));
        
        let tcp_stream = TcpStream::connect((host, port)).await
            .map_err(|e| IronError::Connection(format!("Failed to connect: {}", e)))?;

        tcp_stream.set_nodelay(true)
            .map_err(|e| IronError::Connection(format!("Failed to set nodelay: {}", e)))?;

        let server_name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| IronError::Tls(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| IronError::Tls(format!("TLS handshake failed: {}", e)))?;
        
        Ok(Self {
            stream: tls_stream,
            last_activity: Instant::now(),
            server_name: host.to_string(),
        })
    }

    pub async fn read_message(&mut self) -> Result<Option<IrcMessage>> {
        let mut line = String::new();
        let mut reader = tokio::io::BufReader::new(&mut self.stream);
        
        match tokio::time::timeout(Duration::from_secs(300), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                info!("Connection closed by server");
                return Ok(None);
            }
            Ok(Ok(_)) => {
                self.last_activity = Instant::now();
                debug!("Received: {}", line.trim());
                
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

                match line.parse::<IrcMessage>() {
                    Ok(msg) => Ok(Some(msg)),
                    Err(e) => {
                        error!("Failed to parse message '{}': {}", line.trim(), e);
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
        
        if serialized.len() > 8704 {
            return Err(IronError::SecurityViolation(
                "Outgoing message too long".to_string()
            ));
        }

        debug!("Sending: {}", serialized.trim());
        
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

        debug!("Sending raw: {}", line.trim());
        
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