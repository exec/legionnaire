use std::fmt;

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
        }
    }
}

impl std::error::Error for IronError {}

impl From<std::io::Error> for IronError {
    fn from(err: std::io::Error) -> Self {
        IronError::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, IronError>;