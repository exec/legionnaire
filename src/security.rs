//! Security Hardening and Threat Mitigation
//!
//! Provides comprehensive security measures including input validation,
//! DoS protection, secure defaults, and threat detection for production deployments.

use crate::error::{IronError, Result};
use anyhow::anyhow;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use std::net::IpAddr;
use std::sync::Arc;

/// Security configuration for production deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable comprehensive input validation
    pub strict_input_validation: bool,
    /// Maximum message length allowed
    pub max_message_length: usize,
    /// Maximum nick/channel/topic length
    pub max_name_length: usize,
    /// Enable rate limiting per client
    pub enable_rate_limiting: bool,
    /// Messages per minute per client
    pub rate_limit_messages_per_minute: u32,
    /// Enable connection throttling per IP
    pub enable_connection_throttling: bool,
    /// Maximum connections per IP address
    pub max_connections_per_ip: u32,
    /// Enable malicious pattern detection
    pub enable_threat_detection: bool,
    /// Minimum TLS version required
    pub min_tls_version: TlsVersion,
    /// Require certificate verification
    pub require_cert_verification: bool,
    /// Enable secure random number generation
    pub use_secure_random: bool,
    /// Enable audit logging
    pub enable_audit_logging: bool,
    /// Log security events to separate file
    pub security_log_file: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            strict_input_validation: true,
            max_message_length: 512, // RFC 1459 limit
            max_name_length: 50,     // Conservative limit
            enable_rate_limiting: true,
            rate_limit_messages_per_minute: 60, // 1 per second average
            enable_connection_throttling: true,
            max_connections_per_ip: 5,
            enable_threat_detection: true,
            min_tls_version: TlsVersion::V1_3,
            require_cert_verification: true,
            use_secure_random: true,
            enable_audit_logging: true,
            security_log_file: Some("security.log".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

/// Security validator for all user inputs
pub struct SecurityValidator {
    config: SecurityConfig,
    rate_limiters: Arc<RwLock<HashMap<String, RateLimiter>>>,
    connection_tracker: Arc<RwLock<HashMap<IpAddr, ConnectionTracker>>>,
    threat_detector: ThreatDetector,
    audit_logger: Option<AuditLogger>,
}

/// Rate limiting per client
#[derive(Debug)]
struct RateLimiter {
    client_id: String,
    message_timestamps: Vec<Instant>,
    violations: u32,
    blocked_until: Option<Instant>,
}

/// Connection tracking per IP
#[derive(Debug)]
struct ConnectionTracker {
    ip: IpAddr,
    active_connections: u32,
    connection_attempts: Vec<Instant>,
    blocked_until: Option<Instant>,
}

/// Threat detection system
#[derive(Debug)]
pub struct ThreatDetector {
    malicious_patterns: Vec<MaliciousPattern>,
    suspicious_activity: HashMap<String, SuspiciousActivity>,
}

#[derive(Debug, Clone)]
struct MaliciousPattern {
    name: String,
    pattern: regex::Regex,
    severity: ThreatLevel,
    description: String,
}

#[derive(Debug, Clone)]
enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
struct SuspiciousActivity {
    client_id: String,
    events: Vec<SecurityEvent>,
    risk_score: u32,
    last_seen: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: SecurityEventType,
    pub client_id: String,
    pub ip_address: Option<IpAddr>,
    pub description: String,
    pub severity: ThreatLevel,
    pub action_taken: SecurityAction,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityEventType {
    InvalidInput,
    RateLimitViolation,
    SuspiciousPattern,
    ConnectionFlood,
    AuthenticationFailed,
    TlsViolation,
    MaliciousPayload,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityAction {
    Blocked,
    Warning,
    Monitored,
    TemporaryBan,
    PermanentBan,
    Allowed,
}

/// Audit logger for security events
pub struct AuditLogger {
    log_file: String,
}

impl SecurityValidator {
    pub fn new(config: SecurityConfig) -> Result<Self> {
        let audit_logger = if config.enable_audit_logging {
            config.security_log_file.as_ref()
                .map(|file| AuditLogger::new(file))
                .transpose()?
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            connection_tracker: Arc::new(RwLock::new(HashMap::new())),
            threat_detector: ThreatDetector::new()?,
            audit_logger,
        })
    }

    /// Validate IRC message before processing
    pub async fn validate_message(&self, client_id: &str, message: &str, ip: Option<IpAddr>) -> Result<()> {
        // Check message length
        if self.config.strict_input_validation && message.len() > self.config.max_message_length {
            let event = SecurityEvent {
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::InvalidInput,
                client_id: client_id.to_string(),
                ip_address: ip,
                description: format!("Message exceeds length limit: {} > {}", 
                    message.len(), self.config.max_message_length),
                severity: ThreatLevel::Medium,
                action_taken: SecurityAction::Blocked,
            };
            
            self.log_security_event(&event).await;
            return Err(IronError::SecurityViolation("Message too long".to_string()));
        }

        // Check for malicious patterns
        if self.config.enable_threat_detection {
            if let Some(threat) = self.threat_detector.detect_threat(message) {
                let event = SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: SecurityEventType::MaliciousPayload,
                    client_id: client_id.to_string(),
                    ip_address: ip,
                    description: format!("Malicious pattern detected: {}", threat.name),
                    severity: threat.severity.clone(),
                    action_taken: match threat.severity {
                        ThreatLevel::Critical => SecurityAction::PermanentBan,
                        ThreatLevel::High => SecurityAction::TemporaryBan,
                        _ => SecurityAction::Blocked,
                    },
                };
                
                self.log_security_event(&event).await;
                return Err(IronError::SecurityViolation(format!("Malicious content: {}", threat.name)));
            }
        }

        // Rate limiting check
        if self.config.enable_rate_limiting {
            if !self.check_rate_limit(client_id, ip).await? {
                let event = SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: SecurityEventType::RateLimitViolation,
                    client_id: client_id.to_string(),
                    ip_address: ip,
                    description: "Rate limit exceeded".to_string(),
                    severity: ThreatLevel::Medium,
                    action_taken: SecurityAction::TemporaryBan,
                };
                
                self.log_security_event(&event).await;
                return Err(IronError::SecurityViolation("Rate limit exceeded".to_string()));
            }
        }

        // Input sanitization
        self.sanitize_input(message)?;

        Ok(())
    }

    /// Check if connection is allowed from IP
    pub async fn validate_connection(&self, ip: IpAddr) -> Result<()> {
        if !self.config.enable_connection_throttling {
            return Ok(());
        }

        let mut tracker = self.connection_tracker.write().await;
        let connection_info = tracker.entry(ip).or_insert_with(|| ConnectionTracker {
            ip,
            active_connections: 0,
            connection_attempts: Vec::new(),
            blocked_until: None,
        });

        // Check if currently blocked
        if let Some(blocked_until) = connection_info.blocked_until {
            if Instant::now() < blocked_until {
                return Err(IronError::SecurityViolation("IP temporarily blocked".to_string()));
            } else {
                connection_info.blocked_until = None;
                connection_info.connection_attempts.clear();
            }
        }

        // Check connection limit
        if connection_info.active_connections >= self.config.max_connections_per_ip {
            let event = SecurityEvent {
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::ConnectionFlood,
                client_id: format!("ip:{}", ip),
                ip_address: Some(ip),
                description: format!("Too many connections from IP: {}", connection_info.active_connections),
                severity: ThreatLevel::High,
                action_taken: SecurityAction::TemporaryBan,
            };
            
            self.log_security_event(&event).await;
            
            // Block IP for 5 minutes
            connection_info.blocked_until = Some(Instant::now() + Duration::from_secs(300));
            return Err(IronError::SecurityViolation("Too many connections from IP".to_string()));
        }

        // Track this connection attempt
        connection_info.connection_attempts.push(Instant::now());
        connection_info.active_connections += 1;

        // Clean old attempts (older than 1 hour)
        let cutoff = Instant::now() - Duration::from_secs(3600);
        connection_info.connection_attempts.retain(|&time| time > cutoff);

        Ok(())
    }

    /// Validate nickname/channel name
    pub fn validate_name(&self, name_type: &str, name: &str) -> Result<()> {
        if name.len() > self.config.max_name_length {
            return Err(IronError::SecurityViolation(
                format!("{} name too long", name_type)
            ));
        }

        // Check for invalid characters
        if name.contains('\0') || name.contains('\r') || name.contains('\n') {
            return Err(IronError::SecurityViolation(
                format!("Invalid characters in {} name", name_type)
            ));
        }

        // IRC-specific validation
        match name_type {
            "nickname" => {
                if name.is_empty() || name.starts_with('#') || name.contains(' ') {
                    return Err(IronError::SecurityViolation("Invalid nickname format".to_string()));
                }
            }
            "channel" => {
                if !name.starts_with('#') && !name.starts_with('&') {
                    return Err(IronError::SecurityViolation("Invalid channel format".to_string()));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Sanitize user input
    fn sanitize_input(&self, input: &str) -> Result<()> {
        // Check for control characters (except allowed ones)
        for ch in input.chars() {
            if ch.is_control() && ch != '\t' && ch != '\x02' && ch != '\x03' && ch != '\x0F' {
                return Err(IronError::SecurityViolation("Invalid control characters".to_string()));
            }
        }

        // Check for potential injection attempts
        let suspicious_patterns = [
            "\\x00", "\\x01", "\\x7F",  // Null bytes and control chars
            "javascript:", "data:",      // URI schemes
            "<script", "</script>",     // HTML injection
            "eval(", "setTimeout(",      // JS injection
            "UNION SELECT", "DROP TABLE", // SQL injection
        ];

        let lower_input = input.to_lowercase();
        for pattern in &suspicious_patterns {
            if lower_input.contains(pattern) {
                warn!("Suspicious pattern detected in input: {}", pattern);
                return Err(IronError::SecurityViolation("Suspicious input pattern".to_string()));
            }
        }

        Ok(())
    }

    /// Check rate limiting for client
    async fn check_rate_limit(&self, client_id: &str, ip: Option<IpAddr>) -> Result<bool> {
        let mut limiters = self.rate_limiters.write().await;
        let rate_limiter = limiters.entry(client_id.to_string()).or_insert_with(|| RateLimiter {
            client_id: client_id.to_string(),
            message_timestamps: Vec::new(),
            violations: 0,
            blocked_until: None,
        });

        let now = Instant::now();

        // Check if currently blocked
        if let Some(blocked_until) = rate_limiter.blocked_until {
            if now < blocked_until {
                return Ok(false);
            } else {
                rate_limiter.blocked_until = None;
                rate_limiter.violations = 0;
            }
        }

        // Clean old timestamps (older than 1 minute)
        let cutoff = now - Duration::from_secs(60);
        rate_limiter.message_timestamps.retain(|&time| time > cutoff);

        // Check if rate limit exceeded
        if rate_limiter.message_timestamps.len() >= self.config.rate_limit_messages_per_minute as usize {
            rate_limiter.violations += 1;
            
            // Progressive blocking: 1 min, 5 min, 15 min, 1 hour
            let block_duration = match rate_limiter.violations {
                1 => Duration::from_secs(60),
                2 => Duration::from_secs(300),
                3 => Duration::from_secs(900),
                _ => Duration::from_secs(3600),
            };
            
            rate_limiter.blocked_until = Some(now + block_duration);
            
            warn!("Rate limit exceeded for client {} (violation #{})", 
                client_id, rate_limiter.violations);
            return Ok(false);
        }

        // Record this message
        rate_limiter.message_timestamps.push(now);
        Ok(true)
    }

    /// Log security event
    async fn log_security_event(&self, event: &SecurityEvent) {
        if let Some(ref logger) = self.audit_logger {
            if let Err(e) = logger.log_event(event).await {
                error!("Failed to log security event: {}", e);
            }
        }

        match event.severity {
            ThreatLevel::Critical => error!("SECURITY: {}", event.description),
            ThreatLevel::High => warn!("SECURITY: {}", event.description),
            ThreatLevel::Medium => warn!("Security: {}", event.description),
            ThreatLevel::Low => debug!("Security: {}", event.description),
        }
    }

    /// Get security statistics
    pub async fn get_security_stats(&self) -> SecurityStats {
        let limiters = self.rate_limiters.read().await;
        let tracker = self.connection_tracker.read().await;

        SecurityStats {
            active_rate_limits: limiters.len(),
            blocked_clients: limiters.values().filter(|l| l.blocked_until.is_some()).count(),
            active_connections: tracker.values().map(|t| t.active_connections).sum(),
            blocked_ips: tracker.values().filter(|t| t.blocked_until.is_some()).count(),
            total_violations: limiters.values().map(|l| l.violations).sum(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SecurityStats {
    pub active_rate_limits: usize,
    pub blocked_clients: usize,
    pub active_connections: u32,
    pub blocked_ips: usize,
    pub total_violations: u32,
}

impl ThreatDetector {
    fn new() -> Result<Self> {
        let malicious_patterns = Self::load_malicious_patterns()?;
        
        Ok(Self {
            malicious_patterns,
            suspicious_activity: HashMap::new(),
        })
    }

    fn load_malicious_patterns() -> Result<Vec<MaliciousPattern>> {
        use regex::Regex;
        
        let patterns = vec![
            // Command injection attempts
            ("command_injection", r"[;&|`$].*\b(rm|del|format|shutdown|reboot)\b", ThreatLevel::Critical),
            // Path traversal
            ("path_traversal", r"\.\./|\\\.\.\\|%2e%2e%2f", ThreatLevel::High),
            // Script injection
            ("script_injection", r"<script.*?>.*?</script>|javascript:", ThreatLevel::High),
            // Buffer overflow attempts
            ("buffer_overflow", r"[A-Za-z0-9+/]{1000,}", ThreatLevel::Medium),
            // CTCP floods
            ("ctcp_flood", r"\x01.*?\x01", ThreatLevel::Medium),
            // IRC command spam
            ("irc_spam", r"(JOIN|PART|QUIT|NICK)\s+", ThreatLevel::Low),
        ];

        let mut result = Vec::new();
        for (name, pattern_str, severity) in patterns {
            match Regex::new(pattern_str) {
                Ok(regex) => {
                    result.push(MaliciousPattern {
                        name: name.to_string(),
                        pattern: regex,
                        severity,
                        description: format!("Detects {} attempts", name),
                    });
                }
                Err(e) => {
                    error!("Failed to compile regex pattern {}: {}", name, e);
                }
            }
        }

        Ok(result)
    }

    fn detect_threat(&self, input: &str) -> Option<&MaliciousPattern> {
        for pattern in &self.malicious_patterns {
            if pattern.pattern.is_match(input) {
                return Some(pattern);
            }
        }
        None
    }
}

impl AuditLogger {
    fn new(log_file: &str) -> Result<Self> {
        // Ensure log directory exists
        if let Some(parent) = std::path::Path::new(log_file).parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(Self {
            log_file: log_file.to_string(),
        })
    }

    async fn log_event(&self, event: &SecurityEvent) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        
        let log_entry = serde_json::to_string(event)
            .map_err(|e| IronError::Configuration(format!("Failed to serialize security event: {}", e)))?;
        
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .await?;
        
        file.write_all(format!("{}\n", log_entry).as_bytes()).await?;
        file.flush().await?;
        
        Ok(())
    }
}

impl Serialize for ThreatLevel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ThreatLevel::Low => serializer.serialize_str("low"),
            ThreatLevel::Medium => serializer.serialize_str("medium"),
            ThreatLevel::High => serializer.serialize_str("high"),
            ThreatLevel::Critical => serializer.serialize_str("critical"),
        }
    }
}

/// Helper functions for security integration
pub mod helpers {
    use super::*;
    
    /// Create production security configuration
    pub fn production_security_config() -> SecurityConfig {
        SecurityConfig {
            strict_input_validation: true,
            max_message_length: 512,
            max_name_length: 32,
            enable_rate_limiting: true,
            rate_limit_messages_per_minute: 30, // Stricter for production
            enable_connection_throttling: true,
            max_connections_per_ip: 3, // Stricter limit
            enable_threat_detection: true,
            min_tls_version: TlsVersion::V1_3,
            require_cert_verification: true,
            use_secure_random: true,
            enable_audit_logging: true,
            security_log_file: Some("logs/security.jsonl".to_string()),
        }
    }
    
    /// Create development security configuration (more permissive)
    pub fn development_security_config() -> SecurityConfig {
        SecurityConfig {
            strict_input_validation: false,
            max_message_length: 1024,
            max_name_length: 100,
            enable_rate_limiting: false,
            rate_limit_messages_per_minute: 120,
            enable_connection_throttling: false,
            max_connections_per_ip: 10,
            enable_threat_detection: false,
            min_tls_version: TlsVersion::V1_2,
            require_cert_verification: false,
            use_secure_random: true,
            enable_audit_logging: false,
            security_log_file: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, IpAddr};

    #[tokio::test]
    async fn test_message_validation() -> Result<()> {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config)?;

        // Valid message
        assert!(validator.validate_message("test_client", "Hello world!", None).await.is_ok());

        // Message too long
        let long_message = "a".repeat(600);
        assert!(validator.validate_message("test_client", &long_message, None).await.is_err());

        // Malicious pattern
        assert!(validator.validate_message("test_client", "rm -rf /", None).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_throttling() -> Result<()> {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config)?;
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // First few connections should succeed
        for _ in 0..3 {
            assert!(validator.validate_connection(test_ip).await.is_ok());
        }

        // Exceed limit
        for _ in 0..3 {
            assert!(validator.validate_connection(test_ip).await.is_err());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let mut config = SecurityConfig::default();
        config.rate_limit_messages_per_minute = 2; // Very low for testing
        let validator = SecurityValidator::new(config)?;

        // First messages should succeed
        assert!(validator.validate_message("test_client", "message 1", None).await.is_ok());
        assert!(validator.validate_message("test_client", "message 2", None).await.is_ok());

        // Rate limit should kick in
        assert!(validator.validate_message("test_client", "message 3", None).await.is_err());

        Ok(())
    }

    #[test]
    fn test_name_validation() -> Result<()> {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config)?;

        // Valid names
        assert!(validator.validate_name("nickname", "alice").is_ok());
        assert!(validator.validate_name("channel", "#general").is_ok());

        // Invalid names
        assert!(validator.validate_name("nickname", "").is_err());
        assert!(validator.validate_name("nickname", "#alice").is_err());
        assert!(validator.validate_name("channel", "general").is_err());
        assert!(validator.validate_name("nickname", "alice with spaces").is_err());

        // Name too long
        let long_name = "a".repeat(100);
        assert!(validator.validate_name("nickname", &long_name).is_err());

        Ok(())
    }

    #[test]
    fn test_threat_detection() -> Result<()> {
        let detector = ThreatDetector::new()?;

        // Should detect command injection
        assert!(detector.detect_threat("rm -rf /home").is_some());
        assert!(detector.detect_threat("shutdown -h now").is_some());

        // Should detect path traversal
        assert!(detector.detect_threat("../../../etc/passwd").is_some());

        // Should detect script injection
        assert!(detector.detect_threat("<script>alert('xss')</script>").is_some());

        // Safe input should pass
        assert!(detector.detect_threat("Hello world!").is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_security_stats() -> Result<()> {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config)?;
        let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Generate some activity
        let _ = validator.validate_connection(test_ip).await;
        let _ = validator.validate_message("client1", "test message", Some(test_ip)).await;

        let stats = validator.get_security_stats().await;
        assert!(stats.active_connections > 0);

        Ok(())
    }
}