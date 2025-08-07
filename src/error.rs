use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Registering,
    Registered,
    Reconnecting { attempt: u32, max_attempts: u32 },
    Failed,
}

#[derive(Debug, Clone)]
pub enum DisconnectReason {
    UserRequested,
    ServerError(String),
    NetworkTimeout,
    PingTimeout,
    TlsFailure(String),
    AuthenticationFailed,
    ReadError(String),
    WriteError(String),
    ParseError(String),
    SecurityViolation(String),
}

#[derive(Debug)]
pub enum IronError {
    Connection(String),
    Tls(String), 
    Parse(String),
    Auth(String),
    InvalidMessage(String),
    SecurityViolation(String),
    Configuration(String),
    Io(std::io::Error),
    Reconnect(String),
    Timeout(String),
    NetworkUnavailable(String),
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting"),
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Registering => write!(f, "Registering"),
            ConnectionState::Registered => write!(f, "Registered"),
            ConnectionState::Reconnecting { attempt, max_attempts } => {
                write!(f, "Reconnecting (attempt {}/{})", attempt, max_attempts)
            }
            ConnectionState::Failed => write!(f, "Failed"),
        }
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisconnectReason::UserRequested => write!(f, "User requested"),
            DisconnectReason::ServerError(msg) => write!(f, "Server error: {}", msg),
            DisconnectReason::NetworkTimeout => write!(f, "Network timeout"),
            DisconnectReason::PingTimeout => write!(f, "Ping timeout"),
            DisconnectReason::TlsFailure(msg) => write!(f, "TLS failure: {}", msg),
            DisconnectReason::AuthenticationFailed => write!(f, "Authentication failed"),
            DisconnectReason::ReadError(msg) => write!(f, "Read error: {}", msg),
            DisconnectReason::WriteError(msg) => write!(f, "Write error: {}", msg),
            DisconnectReason::ParseError(msg) => write!(f, "Parse error: {}", msg),
            DisconnectReason::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
        }
    }
}

impl fmt::Display for IronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IronError::Connection(msg) => write!(f, "Connection error: {}", msg),
            IronError::Tls(msg) => write!(f, "TLS error: {}", msg),
            IronError::Parse(msg) => write!(f, "Parse error: {}", msg),
            IronError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            IronError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            IronError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            IronError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            IronError::Io(err) => write!(f, "IO error: {}", err),
            IronError::Reconnect(msg) => write!(f, "Reconnect error: {}", msg),
            IronError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            IronError::NetworkUnavailable(msg) => write!(f, "Network unavailable: {}", msg),
        }
    }
}

impl std::error::Error for IronError {}

impl From<std::io::Error> for IronError {
    fn from(err: std::io::Error) -> Self {
        IronError::Io(err)
    }
}

impl From<iron_protocol::IronError> for IronError {
    fn from(err: iron_protocol::IronError) -> Self {
        match err {
            iron_protocol::IronError::Parse(msg) => IronError::Parse(msg),
            iron_protocol::IronError::SecurityViolation(msg) => IronError::SecurityViolation(msg),
            iron_protocol::IronError::Auth(msg) => IronError::Auth(msg),
            iron_protocol::IronError::Connection(msg) => IronError::Connection(msg),
            iron_protocol::IronError::Protocol(msg) => IronError::Parse(msg),
            iron_protocol::IronError::RateLimit(msg) => IronError::SecurityViolation(msg),
            iron_protocol::IronError::Config(msg) => IronError::Configuration(msg),
            iron_protocol::IronError::Capability(msg) => IronError::Configuration(msg),
            iron_protocol::IronError::Sasl(msg) => IronError::Auth(msg),
            iron_protocol::IronError::Io(msg) => IronError::Connection(msg),
            iron_protocol::IronError::Timeout(msg) => IronError::Timeout(msg),
            iron_protocol::IronError::InvalidInput(msg) => IronError::InvalidMessage(msg),
            iron_protocol::IronError::NotSupported(msg) => IronError::Configuration(msg),
            iron_protocol::IronError::Internal(msg) => IronError::Connection(msg),
        }
    }
}

impl From<IronError> for iron_protocol::IronError {
    fn from(err: IronError) -> Self {
        match err {
            IronError::Connection(msg) => iron_protocol::IronError::Connection(msg),
            IronError::Tls(msg) => iron_protocol::IronError::Connection(msg),
            IronError::Parse(msg) => iron_protocol::IronError::Parse(msg),
            IronError::Auth(msg) => iron_protocol::IronError::Auth(msg),
            IronError::InvalidMessage(msg) => iron_protocol::IronError::InvalidInput(msg),
            IronError::SecurityViolation(msg) => iron_protocol::IronError::SecurityViolation(msg),
            IronError::Configuration(msg) => iron_protocol::IronError::Config(msg),
            IronError::Io(io_err) => iron_protocol::IronError::Io(io_err.to_string()),
            IronError::Reconnect(msg) => iron_protocol::IronError::Connection(msg),
            IronError::Timeout(msg) => iron_protocol::IronError::Timeout(msg),
            IronError::NetworkUnavailable(msg) => iron_protocol::IronError::Connection(msg),
        }
    }
}

pub type Result<T> = std::result::Result<T, IronError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use test_case::test_case;

    // Error creation and display tests
    #[test]
    fn test_connection_error() {
        let error = IronError::Connection("Failed to connect to server".to_string());
        assert_eq!(error.to_string(), "Connection error: Failed to connect to server");
    }

    #[test]
    fn test_tls_error() {
        let error = IronError::Tls("Invalid certificate".to_string());
        assert_eq!(error.to_string(), "TLS error: Invalid certificate");
    }

    #[test]
    fn test_parse_error() {
        let error = IronError::Parse("Invalid message format".to_string());
        assert_eq!(error.to_string(), "Parse error: Invalid message format");
    }

    #[test]
    fn test_auth_error() {
        let error = IronError::Auth("Authentication failed".to_string());
        assert_eq!(error.to_string(), "Authentication error: Authentication failed");
    }

    #[test]
    fn test_invalid_message_error() {
        let error = IronError::InvalidMessage("Message exceeds length limit".to_string());
        assert_eq!(error.to_string(), "Invalid message: Message exceeds length limit");
    }

    #[test]
    fn test_security_violation_error() {
        let error = IronError::SecurityViolation("Malicious input detected".to_string());
        assert_eq!(error.to_string(), "Security violation: Malicious input detected");
    }

    #[test]
    fn test_configuration_error() {
        let error = IronError::Configuration("Invalid config file".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid config file");
    }

    #[test]
    fn test_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
        let error = IronError::Io(io_err);
        assert!(error.to_string().contains("IO error"));
        assert!(error.to_string().contains("Access denied"));
    }

    // Error conversion tests
    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "File not found");
        let iron_error: IronError = io_err.into();
        
        match iron_error {
            IronError::Io(ref e) => {
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
                assert_eq!(e.to_string(), "File not found");
            }
            _ => panic!("Expected Io error"),
        }
    }

    // Error trait implementation tests
    #[test]
    fn test_error_trait() {
        let error = IronError::Connection("Test error".to_string());
        
        // Test that it implements Error trait
        assert!(std::error::Error::source(&error).is_none());
        
        // Test debug formatting
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Connection"));
        assert!(debug_str.contains("Test error"));
    }

    #[test]
    fn test_io_error_chain() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused");
        let iron_error = IronError::Io(io_err);
        
        // Test error source chain
        if let IronError::Io(ref io_error) = iron_error {
            assert!(std::error::Error::source(io_error).is_none());
        } else {
            panic!("Expected Io error");
        }
    }

    // Error matching and type checking tests
    #[test_case(IronError::Connection("test".to_string()); "connection")]
    #[test_case(IronError::Tls("test".to_string()); "tls")]
    #[test_case(IronError::Parse("test".to_string()); "parse")]
    #[test_case(IronError::Auth("test".to_string()); "auth")]
    #[test_case(IronError::InvalidMessage("test".to_string()); "invalid_message")]
    #[test_case(IronError::SecurityViolation("test".to_string()); "security_violation")]
    #[test_case(IronError::Configuration("test".to_string()); "configuration")]
    #[test_case(IronError::Reconnect("test".to_string()); "reconnect")]
    #[test_case(IronError::Timeout("test".to_string()); "timeout")]
    #[test_case(IronError::NetworkUnavailable("test".to_string()); "network_unavailable")]
    fn test_error_variants(error: IronError) {
        // Test that each variant can be created and matched
        match error {
            IronError::Connection(_) => assert!(matches!(error, IronError::Connection(_))),
            IronError::Tls(_) => assert!(matches!(error, IronError::Tls(_))),
            IronError::Parse(_) => assert!(matches!(error, IronError::Parse(_))),
            IronError::Auth(_) => assert!(matches!(error, IronError::Auth(_))),
            IronError::InvalidMessage(_) => assert!(matches!(error, IronError::InvalidMessage(_))),
            IronError::SecurityViolation(_) => assert!(matches!(error, IronError::SecurityViolation(_))),
            IronError::Configuration(_) => assert!(matches!(error, IronError::Configuration(_))),
            IronError::Io(_) => assert!(matches!(error, IronError::Io(_))),
            IronError::Reconnect(_) => assert!(matches!(error, IronError::Reconnect(_))),
            IronError::Timeout(_) => assert!(matches!(error, IronError::Timeout(_))),
            IronError::NetworkUnavailable(_) => assert!(matches!(error, IronError::NetworkUnavailable(_))),
        }
    }

    // Result type tests
    #[test]
    fn test_result_type_ok() {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<i32> = Err(IronError::Connection("Failed".to_string()));
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error, IronError::Connection(_)));
    }

    // Error message content validation tests
    #[test]
    fn test_empty_error_messages() {
        let errors = vec![
            IronError::Connection(String::new()),
            IronError::Tls(String::new()),
            IronError::Parse(String::new()),
            IronError::Auth(String::new()),
            IronError::InvalidMessage(String::new()),
            IronError::SecurityViolation(String::new()),
            IronError::Configuration(String::new()),
        ];
        
        for error in errors {
            let message = error.to_string();
            // Even with empty inner message, should have error type prefix
            assert!(!message.is_empty());
        }
    }

    #[test]
    fn test_long_error_messages() {
        let long_message = "a".repeat(1000);
        let error = IronError::Connection(long_message.clone());
        let display_message = error.to_string();
        
        assert!(display_message.contains(&long_message));
        assert!(display_message.starts_with("Connection error:"));
    }

    #[test]
    fn test_special_characters_in_error_messages() {
        let special_message = "Error with unicode: 🚨 and newlines:\nLine 2\nLine 3";
        let error = IronError::SecurityViolation(special_message.to_string());
        let display_message = error.to_string();
        
        assert!(display_message.contains("🚨"));
        assert!(display_message.contains("Line 2"));
        assert!(display_message.contains("Line 3"));
    }

    // Error categorization tests
    fn is_recoverable_error(error: &IronError) -> bool {
        match error {
            IronError::Connection(_) => true,  // Might reconnect
            IronError::Tls(_) => false,        // Security critical
            IronError::Parse(_) => true,       // Skip bad message
            IronError::Auth(_) => false,       // Credential issue
            IronError::InvalidMessage(_) => true, // Skip bad message
            IronError::SecurityViolation(_) => false, // Security critical
            IronError::Configuration(_) => false, // User must fix
            IronError::Reconnect(_) => true,   // Explicitly recoverable
            IronError::Timeout(_) => true,     // Temporary issue
            IronError::NetworkUnavailable(_) => true, // Temporary issue
            IronError::Io(ref io_err) => {
                match io_err.kind() {
                    io::ErrorKind::TimedOut => true,
                    io::ErrorKind::Interrupted => true,
                    io::ErrorKind::WouldBlock => true,
                    _ => false,
                }
            }
        }
    }

    #[test]
    fn test_error_recoverability() {
        // Recoverable errors
        assert!(is_recoverable_error(&IronError::Connection("Timeout".to_string())));
        assert!(is_recoverable_error(&IronError::Parse("Bad format".to_string())));
        assert!(is_recoverable_error(&IronError::InvalidMessage("Too long".to_string())));
        
        let timeout_io = io::Error::new(io::ErrorKind::TimedOut, "Timeout");
        assert!(is_recoverable_error(&IronError::Io(timeout_io)));
        
        // Non-recoverable errors
        assert!(!is_recoverable_error(&IronError::Tls("Cert error".to_string())));
        assert!(!is_recoverable_error(&IronError::Auth("Bad password".to_string())));
        assert!(!is_recoverable_error(&IronError::SecurityViolation("Attack".to_string())));
        assert!(!is_recoverable_error(&IronError::Configuration("Bad config".to_string())));
        
        let perm_denied_io = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
        assert!(!is_recoverable_error(&IronError::Io(perm_denied_io)));
    }

    // Error chaining and context tests
    #[test]
    fn test_error_with_context() {
        let original_io = io::Error::new(io::ErrorKind::NotFound, "config.toml");
        let config_error = IronError::Configuration(
            format!("Failed to load configuration: {}", original_io)
        );
        
        let message = config_error.to_string();
        assert!(message.contains("Configuration error"));
        assert!(message.contains("Failed to load configuration"));
        assert!(message.contains("config.toml"));
    }

    // Serialization and debugging tests
    #[test]
    fn test_error_debug_format() {
        let errors = vec![
            IronError::Connection("Debug test".to_string()),
            IronError::Tls("TLS debug".to_string()),
            IronError::Parse("Parse debug".to_string()),
            IronError::Auth("Auth debug".to_string()),
            IronError::InvalidMessage("Message debug".to_string()),
            IronError::SecurityViolation("Security debug".to_string()),
            IronError::Configuration("Config debug".to_string()),
            IronError::Io(io::Error::new(io::ErrorKind::Other, "IO debug")),
        ];
        
        for error in errors {
            let debug_str = format!("{:?}", error);
            // Debug format should be more detailed than display format
            assert!(!debug_str.is_empty());
            assert_ne!(debug_str, error.to_string());
        }
    }

    // Error equality and comparison tests
    #[test]
    fn test_error_variant_discrimination() {
        let conn_error1 = IronError::Connection("test".to_string());
        let conn_error2 = IronError::Connection("different".to_string());
        let tls_error = IronError::Tls("test".to_string());
        
        // Same variant, different messages
        assert!(std::mem::discriminant(&conn_error1) == std::mem::discriminant(&conn_error2));
        
        // Different variants
        assert!(std::mem::discriminant(&conn_error1) != std::mem::discriminant(&tls_error));
    }

    // Error handling pattern tests
    #[test]
    fn test_error_handling_patterns() {
        fn handle_error(error: IronError) -> String {
            match error {
                IronError::Connection(msg) => format!("Retrying connection: {}", msg),
                IronError::Tls(msg) => format!("TLS error, aborting: {}", msg),
                IronError::Parse(msg) => format!("Skipping malformed message: {}", msg),
                IronError::Auth(msg) => format!("Authentication required: {}", msg),
                IronError::InvalidMessage(msg) => format!("Ignoring invalid message: {}", msg),
                IronError::SecurityViolation(msg) => format!("SECURITY ALERT: {}", msg),
                IronError::Configuration(msg) => format!("Please fix configuration: {}", msg),
                IronError::Reconnect(msg) => format!("Reconnecting: {}", msg),
                IronError::Timeout(msg) => format!("Timeout occurred: {}", msg),
                IronError::NetworkUnavailable(msg) => format!("Network unavailable: {}", msg),
                IronError::Io(ref io_err) => {
                    match io_err.kind() {
                        io::ErrorKind::TimedOut => "Timeout, retrying...".to_string(),
                        io::ErrorKind::PermissionDenied => "Permission denied, check privileges".to_string(),
                        _ => format!("IO error: {}", io_err),
                    }
                }
            }
        }
        
        let test_cases = vec![
            (IronError::Connection("timeout".to_string()), "Retrying connection"),
            (IronError::Tls("bad cert".to_string()), "TLS error, aborting"),
            (IronError::SecurityViolation("attack".to_string()), "SECURITY ALERT"),
        ];
        
        for (error, expected_prefix) in test_cases {
            let result = handle_error(error);
            assert!(result.starts_with(expected_prefix));
        }
    }

    // Performance and memory tests
    #[test]
    fn test_error_size() {
        // Ensure error types don't consume excessive memory
        let size = std::mem::size_of::<IronError>();
        // Should be reasonable size (this is a rough check)
        assert!(size < 1000, "Error type too large: {} bytes", size);
    }

    #[test]
    fn test_many_errors_creation() {
        // Test creating many errors doesn't cause issues
        let errors: Vec<IronError> = (0..1000)
            .map(|i| IronError::Connection(format!("Error {}", i)))
            .collect();
        
        assert_eq!(errors.len(), 1000);
        assert_eq!(errors[999].to_string(), "Connection error: Error 999");
    }

    // Integration with other error types tests
    #[test]
    fn test_box_error_compatibility() {
        let iron_error = IronError::Connection("test".to_string());
        let boxed: Box<dyn std::error::Error> = Box::new(iron_error);
        
        let display_msg = boxed.to_string();
        assert!(display_msg.contains("Connection error"));
    }

    #[test]
    fn test_anyhow_compatibility() {
        use anyhow::Context;
        
        let result: anyhow::Result<()> = Err(IronError::Auth("Failed".to_string()))
            .context("During connection attempt");
        
        assert!(result.is_err());
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("During connection attempt"));
        assert!(error_msg.contains("Authentication error"));
    }

    // Error recovery strategies tests
    #[derive(Debug)]
    enum RecoveryAction {
        Retry,
        Skip,
        Abort,
        Reconfigure,
    }

    fn determine_recovery_action(error: &IronError) -> RecoveryAction {
        match error {
            IronError::Connection(_) => RecoveryAction::Retry,
            IronError::Parse(_) | IronError::InvalidMessage(_) => RecoveryAction::Skip,
            IronError::Configuration(_) => RecoveryAction::Reconfigure,
            IronError::Tls(_) | IronError::Auth(_) | IronError::SecurityViolation(_) => RecoveryAction::Abort,
            IronError::Reconnect(_) | IronError::Timeout(_) | IronError::NetworkUnavailable(_) => RecoveryAction::Retry,
            IronError::Io(io_err) => {
                match io_err.kind() {
                    io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => RecoveryAction::Retry,
                    io::ErrorKind::PermissionDenied => RecoveryAction::Reconfigure,
                    _ => RecoveryAction::Abort,
                }
            }
        }
    }

    #[test]
    fn test_recovery_strategies() {
        let test_cases = vec![
            (IronError::Connection("timeout".to_string()), RecoveryAction::Retry),
            (IronError::Parse("bad format".to_string()), RecoveryAction::Skip),
            (IronError::Auth("bad password".to_string()), RecoveryAction::Abort),
            (IronError::Configuration("missing file".to_string()), RecoveryAction::Reconfigure),
        ];
        
        for (error, expected_action) in test_cases {
            let action = determine_recovery_action(&error);
            assert!(matches!((action, expected_action), 
                (RecoveryAction::Retry, RecoveryAction::Retry) |
                (RecoveryAction::Skip, RecoveryAction::Skip) |
                (RecoveryAction::Abort, RecoveryAction::Abort) |
                (RecoveryAction::Reconfigure, RecoveryAction::Reconfigure)
            ));
        }
    }
}