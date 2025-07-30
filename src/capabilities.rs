use crate::error::{IronError, Result};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use crate::{iron_debug, iron_info, iron_warn};

#[derive(Debug, Clone)]
pub struct Capability {
    pub name: String,
    pub value: Option<String>,
    pub enabled: bool,
}

pub struct CapabilityHandler {
    version: u16,
    available_caps: HashMap<String, Capability>,
    requested_caps: Vec<String>,
    enabled_caps: HashMap<String, Capability>,
    negotiation_complete: bool,
    sts_policies: HashMap<String, StsPolicy>,
}

#[derive(Debug, Clone)]
pub struct StsPolicy {
    pub duration: Duration,
    pub port: Option<u16>,
    pub preload: bool,
    pub expires_at: SystemTime,
}

impl CapabilityHandler {
    pub fn new() -> Self {
        Self {
            version: 302,
            available_caps: HashMap::new(),
            requested_caps: Vec::new(),
            enabled_caps: HashMap::new(),
            negotiation_complete: false,
            sts_policies: HashMap::new(),
        }
    }

    pub fn handle_cap_ls(&mut self, params: &[String]) -> Result<bool> {
        if params.len() < 2 {
            return Err(IronError::Parse("Invalid CAP LS response".to_string()));
        }

        let is_multiline = params.len() > 2 && params[1] == "*";
        let caps_list = if is_multiline { &params[2] } else { &params[1] };
        
        self.parse_capabilities(caps_list)?;
        
        iron_debug!("capabilities", "Parsed capabilities: {:?}", self.available_caps.keys().collect::<Vec<_>>());
        
        Ok(!is_multiline)
    }

    pub fn handle_cap_ack(&mut self, caps: &[String]) -> Result<()> {
        for cap_name in caps {
            if let Some(cap) = self.available_caps.get(cap_name) {
                let mut enabled_cap = cap.clone();
                enabled_cap.enabled = true;
                self.enabled_caps.insert(cap_name.clone(), enabled_cap);
                iron_info!("capabilities", "Capability enabled: {}", cap_name);
            }
        }
        Ok(())
    }

    pub fn handle_cap_nak(&mut self, caps: &[String]) -> Result<()> {
        for cap in caps {
            if self.get_essential_capabilities().contains(&cap.as_str()) {
                if matches!(cap.as_str(), "sasl" | "sts") {
                    return Err(IronError::SecurityViolation(
                        format!("Essential security capability rejected: {}", cap)
                    ));
                }
            }
            
            self.requested_caps.retain(|c| c != cap);
            iron_warn!("capabilities", "Capability rejected: {}", cap);
        }
        Ok(())
    }

    pub fn handle_cap_new(&mut self, caps_str: &str) -> Result<Vec<String>> {
        if self.version < 302 {
            return Ok(Vec::new());
        }

        self.parse_capabilities(caps_str)?;
        
        let mut new_requests = Vec::new();
        for cap_name in caps_str.split_whitespace() {
            let cap_name = cap_name.split('=').next().unwrap_or(cap_name);
            if self.get_essential_capabilities().contains(&cap_name) {
                new_requests.push(cap_name.to_string());
            }
        }

        iron_info!("capabilities", "New capabilities available: {:?}", new_requests);
        Ok(new_requests)
    }

    pub fn handle_cap_del(&mut self, caps: &[String]) -> Result<()> {
        for cap in caps {
            self.available_caps.remove(cap);
            self.enabled_caps.remove(cap);
            
            if matches!(cap.as_str(), "sasl" | "sts") {
                iron_warn!("capabilities", "Lost critical security capability: {}", cap);
            }
        }
        Ok(())
    }

    pub fn get_capabilities_to_request(&self) -> Vec<String> {
        let mut caps_to_request = Vec::new();
        
        for &cap_name in &self.get_essential_capabilities() {
            if self.available_caps.contains_key(cap_name) {
                caps_to_request.push(cap_name.to_string());
            }
        }

        if let Some(sasl_cap) = self.available_caps.get("sasl") {
            if let Err(e) = self.validate_sasl_mechanisms(sasl_cap) {
                iron_warn!("capabilities", "SASL validation failed: {}", e);
                caps_to_request.retain(|c| c != "sasl");
            }
        }

        caps_to_request
    }

    pub fn is_capability_enabled(&self, cap_name: &str) -> bool {
        self.enabled_caps.contains_key(cap_name)
    }

    pub fn get_sasl_mechanisms(&self) -> Vec<String> {
        if let Some(sasl_cap) = self.enabled_caps.get("sasl") {
            if let Some(value) = &sasl_cap.value {
                return value.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
        Vec::new()
    }

    pub fn set_negotiation_complete(&mut self) {
        self.negotiation_complete = true;
        iron_info!("capabilities", "Capability negotiation complete. Enabled: {:?}", 
               self.enabled_caps.keys().collect::<Vec<_>>());
    }

    pub fn is_negotiation_complete(&self) -> bool {
        self.negotiation_complete
    }

    pub fn handle_sts_policy(&mut self, hostname: &str, cap_value: &str) -> Result<()> {
        let mut duration = None;
        let mut port = None;
        let mut preload = false;
        
        for param in cap_value.split(',') {
            let parts: Vec<&str> = param.splitn(2, '=').collect();
            match parts[0].trim() {
                "duration" => {
                    if parts.len() > 1 {
                        duration = Some(Duration::from_secs(
                            parts[1].parse().map_err(|_| {
                                IronError::Parse("Invalid STS duration".to_string())
                            })?
                        ));
                    }
                }
                "port" => {
                    if parts.len() > 1 {
                        port = Some(parts[1].parse().map_err(|_| {
                            IronError::Parse("Invalid STS port".to_string())
                        })?);
                    }
                }
                "preload" => preload = true,
                _ => {}
            }
        }
        
        let duration = duration.ok_or_else(|| {
            IronError::Parse("STS policy missing duration".to_string())
        })?;
        
        if duration.as_secs() == 0 {
            self.sts_policies.remove(hostname);
            iron_info!("capabilities", "STS policy revoked for {}", hostname);
            return Ok(());
        }
        
        let policy = StsPolicy {
            duration,
            port,
            preload,
            expires_at: SystemTime::now() + duration,
        };
        
        self.sts_policies.insert(hostname.to_string(), policy);
        iron_info!("capabilities", "STS policy set for {}: {:?}", hostname, 
              self.sts_policies.get(hostname));
        
        Ok(())
    }

    pub fn should_upgrade_to_tls(&self, hostname: &str) -> Option<u16> {
        if let Some(policy) = self.sts_policies.get(hostname) {
            if SystemTime::now() < policy.expires_at {
                return policy.port.or(Some(6697));
            }
        }
        None
    }

    fn parse_capabilities(&mut self, caps_str: &str) -> Result<()> {
        for cap_spec in caps_str.split_whitespace() {
            if cap_spec.is_empty() {
                continue;
            }

            let (name, value) = if let Some(eq_pos) = cap_spec.find('=') {
                (&cap_spec[..eq_pos], Some(&cap_spec[eq_pos + 1..]))
            } else {
                (cap_spec, None)
            };

            if !self.is_valid_capability_name(name) {
                return Err(IronError::SecurityViolation(
                    format!("Invalid capability name: {}", name)
                ));
            }

            self.available_caps.insert(name.to_string(), Capability {
                name: name.to_string(),
                value: value.map(String::from),
                enabled: false,
            });
        }
        Ok(())
    }

    fn get_essential_capabilities(&self) -> Vec<&str> {
        vec![
            "sasl",
            "sts", 
            "message-tags",
            "account-tag",
            "server-time",
            "batch",
            "cap-notify",
            "away-notify",
            "extended-join",
            "multi-prefix",
        ]
    }

    fn validate_sasl_mechanisms(&self, sasl_cap: &Capability) -> Result<()> {
        if let Some(value) = &sasl_cap.value {
            let mechanisms: Vec<&str> = value.split(',').collect();
            
            let preferred_order = ["SCRAM-SHA-256", "EXTERNAL", "PLAIN"];
            
            for &preferred in &preferred_order {
                if mechanisms.iter().any(|m| m.trim() == preferred) {
                    return Ok(());
                }
            }
            
            return Err(IronError::Auth(
                "No supported SASL mechanisms".to_string()
            ));
        }
        Ok(())
    }

    fn is_valid_capability_name(&self, name: &str) -> bool {
        if name.is_empty() || name.len() > 64 {
            return false;
        }

        if name.starts_with('-') {
            return false;
        }

        if name.contains('/') {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() != 2 {
                return false;
            }
            
            if parts[0].contains('.') && !parts[0].ends_with(".com") 
                && !parts[0].ends_with(".org") && !parts[0].ends_with(".net") 
                && !parts[0].ends_with(".chat") && !parts[0].ends_with(".in") {
                return false;
            }
        }

        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || 
            c == '-' || c == '/' || c == '.' || c == '_'
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Basic capability parsing tests
    #[test]
    fn test_cap_ls_parsing() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN message-tags".to_string()];
        
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(!complete);
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("message-tags"));
    }

    #[test]
    fn test_cap_ls_single_line() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN message-tags server-time".to_string()];
        
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(complete);
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("message-tags"));
        assert!(handler.available_caps.contains_key("server-time"));
    }

    #[test]
    fn test_cap_ls_multiline() {
        let mut handler = CapabilityHandler::new();
        
        // First line (multiline indicated by "*")
        let params1 = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN message-tags".to_string()];
        let complete1 = handler.handle_cap_ls(&params1).unwrap();
        assert!(!complete1);
        
        // Second line (final)
        let params2 = vec!["nick".to_string(), "LS".to_string(), "server-time batch".to_string()];
        let complete2 = handler.handle_cap_ls(&params2).unwrap();
        assert!(complete2);
        
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("message-tags"));
        assert!(handler.available_caps.contains_key("server-time"));
        assert!(handler.available_caps.contains_key("batch"));
    }

    #[test]
    fn test_cap_ls_empty() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string(), "LS".to_string(), "".to_string()];
        
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(complete);
        assert!(handler.available_caps.is_empty());
    }

    #[test]
    fn test_cap_ls_invalid_params() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string()]; // Too few parameters
        
        let result = handler.handle_cap_ls(&params);
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    // Capability acknowledgment tests
    #[test]
    fn test_cap_ack_success() {
        let mut handler = CapabilityHandler::new();
        
        // First add some available capabilities
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN message-tags server-time".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        // Then acknowledge them
        let ack_caps = vec!["sasl".to_string(), "message-tags".to_string()];
        let result = handler.handle_cap_ack(&ack_caps);
        assert!(result.is_ok());
        
        assert!(handler.enabled_caps.contains_key("sasl"));
        assert!(handler.enabled_caps.contains_key("message-tags"));
        assert!(!handler.enabled_caps.contains_key("server-time"));
        assert_eq!(handler.enabled_caps.len(), 2);
    }

    #[test]
    fn test_cap_ack_unavailable() {
        let mut handler = CapabilityHandler::new();
        
        // Acknowledge a capability that wasn't offered
        let ack_caps = vec!["nonexistent".to_string()];
        let result = handler.handle_cap_ack(&ack_caps);
        assert!(result.is_ok()); // Should not error, just not enable
        
        assert!(!handler.enabled_caps.contains_key("nonexistent"));
    }

    // Capability rejection tests
    #[test]
    fn test_cap_nak_non_essential() {
        let mut handler = CapabilityHandler::new();
        
        let nak_caps = vec!["some-optional-cap".to_string()];
        let result = handler.handle_cap_nak(&nak_caps);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cap_nak_essential_security() {
        let mut handler = CapabilityHandler::new();
        
        let nak_caps = vec!["sasl".to_string()];
        let result = handler.handle_cap_nak(&nak_caps);
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
        
        let nak_caps = vec!["sts".to_string()];
        let result = handler.handle_cap_nak(&nak_caps);
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    // Capability NEW/DEL tests (IRCv3.2)
    #[test]
    fn test_cap_new() {
        let mut handler = CapabilityHandler::new();
        handler.version = 302;
        
        let new_requests = handler.handle_cap_new("sasl=EXTERNAL sts=port=6697").unwrap();
        assert!(new_requests.contains(&"sasl".to_string()));
        assert!(new_requests.contains(&"sts".to_string()));
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("sts"));
    }

    #[test]
    fn test_cap_new_version_301() {
        let mut handler = CapabilityHandler::new();
        handler.version = 301; // Older version
        
        let new_requests = handler.handle_cap_new("sasl=EXTERNAL").unwrap();
        assert!(new_requests.is_empty()); // Should ignore on older versions
    }

    #[test]
    fn test_cap_del() {
        let mut handler = CapabilityHandler::new();
        
        // Add some capabilities first
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN message-tags".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        handler.handle_cap_ack(&vec!["sasl".to_string(), "message-tags".to_string()]).unwrap();
        
        assert!(handler.enabled_caps.contains_key("sasl"));
        assert!(handler.enabled_caps.contains_key("message-tags"));
        
        // Remove one capability
        let del_caps = vec!["sasl".to_string()];
        let result = handler.handle_cap_del(&del_caps);
        assert!(result.is_ok());
        
        assert!(!handler.available_caps.contains_key("sasl"));
        assert!(!handler.enabled_caps.contains_key("sasl"));
        assert!(handler.enabled_caps.contains_key("message-tags"));
    }

    // SASL mechanism parsing tests
    #[test]
    fn test_sasl_mechanism_parsing() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN,EXTERNAL".to_string()];
        
        handler.handle_cap_ls(&params).unwrap();
        handler.handle_cap_ack(&vec!["sasl".to_string()]).unwrap();
        
        let mechanisms = handler.get_sasl_mechanisms();
        assert_eq!(mechanisms, vec!["PLAIN", "EXTERNAL"]);
    }

    #[test]
    fn test_sasl_mechanism_parsing_with_spaces() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN, EXTERNAL , SCRAM-SHA-256".to_string()];
        
        handler.handle_cap_ls(&params).unwrap();
        handler.handle_cap_ack(&vec!["sasl".to_string()]).unwrap();
        
        let mechanisms = handler.get_sasl_mechanisms();
        assert_eq!(mechanisms, vec!["PLAIN", "EXTERNAL", "SCRAM-SHA-256"]);
    }

    #[test]
    fn test_sasl_mechanism_parsing_no_value() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl".to_string()];
        
        handler.handle_cap_ls(&params).unwrap();
        handler.handle_cap_ack(&vec!["sasl".to_string()]).unwrap();
        
        let mechanisms = handler.get_sasl_mechanisms();
        assert!(mechanisms.is_empty());
    }

    #[test]
    fn test_sasl_mechanism_parsing_not_enabled() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN,EXTERNAL".to_string()];
        
        handler.handle_cap_ls(&params).unwrap();
        // Don't acknowledge sasl capability
        
        let mechanisms = handler.get_sasl_mechanisms();
        assert!(mechanisms.is_empty());
    }

    // STS policy tests
    #[test]
    fn test_sts_policy_parsing() {
        let mut handler = CapabilityHandler::new();
        
        handler.handle_sts_policy("irc.example.com", "duration=300,port=6697,preload").unwrap();
        
        assert_eq!(handler.should_upgrade_to_tls("irc.example.com"), Some(6697));
        
        let policy = handler.sts_policies.get("irc.example.com").unwrap();
        assert_eq!(policy.duration.as_secs(), 300);
        assert_eq!(policy.port, Some(6697));
        assert!(policy.preload);
    }

    #[test]
    fn test_sts_policy_minimal() {
        let mut handler = CapabilityHandler::new();
        
        handler.handle_sts_policy("irc.example.com", "duration=600").unwrap();
        
        assert_eq!(handler.should_upgrade_to_tls("irc.example.com"), Some(6697)); // Default port
        
        let policy = handler.sts_policies.get("irc.example.com").unwrap();
        assert_eq!(policy.duration.as_secs(), 600);
        assert_eq!(policy.port, None);
        assert!(!policy.preload);
    }

    #[test]
    fn test_sts_policy_revocation() {
        let mut handler = CapabilityHandler::new();
        
        // Set policy first
        handler.handle_sts_policy("irc.example.com", "duration=300,port=6697").unwrap();
        assert!(handler.sts_policies.contains_key("irc.example.com"));
        
        // Revoke policy with duration=0
        handler.handle_sts_policy("irc.example.com", "duration=0").unwrap();
        assert!(!handler.sts_policies.contains_key("irc.example.com"));
        assert_eq!(handler.should_upgrade_to_tls("irc.example.com"), None);
    }

    #[test]
    fn test_sts_policy_invalid_duration() {
        let mut handler = CapabilityHandler::new();
        
        let result = handler.handle_sts_policy("irc.example.com", "duration=invalid");
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    #[test]
    fn test_sts_policy_missing_duration() {
        let mut handler = CapabilityHandler::new();
        
        let result = handler.handle_sts_policy("irc.example.com", "port=6697,preload");
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    #[test]
    fn test_sts_policy_invalid_port() {
        let mut handler = CapabilityHandler::new();
        
        let result = handler.handle_sts_policy("irc.example.com", "duration=300,port=invalid");
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    // Capability name validation tests
    #[test]
    fn test_cap_name_validation() {
        let long_cap = "a".repeat(65);
        let test_cases = vec![
            ("valid-cap", true),
            ("valid.cap", true),
            ("valid_cap", true),
            ("valid/cap", true),
            ("example.com/cap", true),
            ("123abc", true),
            ("", false),
            ("-invalid", false),
            ("invalid cap", false),
            ("invalid@cap", false),
            (long_cap.as_str(), false),
            ("invalid/domain/cap", false),
            ("invalid.unknown/cap", false),
        ];
        
        let handler = CapabilityHandler::new();
        for (name, expected) in test_cases {
            assert_eq!(handler.is_valid_capability_name(name), expected, "Failed for capability: {}", name);
        }
    }

    // Capability selection tests
    #[test]
    fn test_get_capabilities_to_request() {
        let mut handler = CapabilityHandler::new();
        
        // Add essential capabilities
        let params = vec!["nick".to_string(), "LS".to_string(), 
                         "sasl=PLAIN message-tags server-time batch cap-notify account-tag sts=duration=300".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        let caps_to_request = handler.get_capabilities_to_request();
        
        // Should include all available essential capabilities
        assert!(caps_to_request.contains(&"sasl".to_string()));
        assert!(caps_to_request.contains(&"message-tags".to_string()));
        assert!(caps_to_request.contains(&"server-time".to_string()));
        assert!(caps_to_request.contains(&"batch".to_string()));
        assert!(caps_to_request.contains(&"cap-notify".to_string()));
        assert!(caps_to_request.contains(&"account-tag".to_string()));
        assert!(caps_to_request.contains(&"sts".to_string()));
    }

    #[test]
    fn test_get_capabilities_to_request_partial() {
        let mut handler = CapabilityHandler::new();
        
        // Only add some essential capabilities
        let params = vec!["nick".to_string(), "LS".to_string(), "message-tags server-time".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        let caps_to_request = handler.get_capabilities_to_request();
        
        assert!(caps_to_request.contains(&"message-tags".to_string()));
        assert!(caps_to_request.contains(&"server-time".to_string()));
        assert!(!caps_to_request.contains(&"sasl".to_string()));
        assert!(!caps_to_request.contains(&"sts".to_string()));
    }

    #[test]
    fn test_get_capabilities_to_request_invalid_sasl() {
        let mut handler = CapabilityHandler::new();
        
        // Add sasl with no supported mechanisms
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=UNSUPPORTED,INVALID message-tags".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        let caps_to_request = handler.get_capabilities_to_request();
        
        // Should not include sasl due to unsupported mechanisms
        assert!(!caps_to_request.contains(&"sasl".to_string()));
        assert!(caps_to_request.contains(&"message-tags".to_string()));
    }

    // SASL validation tests
    #[test]
    fn test_validate_sasl_mechanisms_supported() {
        let handler = CapabilityHandler::new();
        let sasl_cap = Capability {
            name: "sasl".to_string(),
            value: Some("SCRAM-SHA-256,PLAIN,EXTERNAL".to_string()),
            enabled: false,
        };
        
        let result = handler.validate_sasl_mechanisms(&sasl_cap);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_sasl_mechanisms_unsupported() {
        let handler = CapabilityHandler::new();
        let sasl_cap = Capability {
            name: "sasl".to_string(),
            value: Some("KERBEROS,DIGEST-MD5".to_string()),
            enabled: false,
        };
        
        let result = handler.validate_sasl_mechanisms(&sasl_cap);
        assert!(matches!(result, Err(IronError::Auth(_))));
    }

    #[test]
    fn test_validate_sasl_mechanisms_no_value() {
        let handler = CapabilityHandler::new();
        let sasl_cap = Capability {
            name: "sasl".to_string(),
            value: None,
            enabled: false,
        };
        
        let result = handler.validate_sasl_mechanisms(&sasl_cap);
        assert!(result.is_ok());
    }

    // Capability checking tests
    #[test]
    fn test_is_capability_enabled() {
        let mut handler = CapabilityHandler::new();
        
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN message-tags".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        assert!(!handler.is_capability_enabled("sasl"));
        assert!(!handler.is_capability_enabled("message-tags"));
        
        handler.handle_cap_ack(&vec!["sasl".to_string()]).unwrap();
        
        assert!(handler.is_capability_enabled("sasl"));
        assert!(!handler.is_capability_enabled("message-tags"));
    }

    // Negotiation state tests
    #[test]
    fn test_negotiation_complete() {
        let mut handler = CapabilityHandler::new();
        
        assert!(!handler.is_negotiation_complete());
        
        handler.set_negotiation_complete();
        
        assert!(handler.is_negotiation_complete());
    }

    // Complex capability parsing tests
    #[test]
    fn test_complex_capability_values() {
        let mut handler = CapabilityHandler::new();
        
        let complex_caps = "sasl=PLAIN,EXTERNAL sts=duration=31536000,port=6697,preload draft/label=value extended-join=account-tag";
        let params = vec!["nick".to_string(), "LS".to_string(), complex_caps.to_string()];
        
        let result = handler.handle_cap_ls(&params);
        assert!(result.is_ok());
        
        assert!(handler.available_caps.contains_key("sasl"));
        assert!(handler.available_caps.contains_key("sts"));
        assert!(handler.available_caps.contains_key("draft/label"));
        assert!(handler.available_caps.contains_key("extended-join"));
        
        // Check values are parsed correctly
        let sasl_cap = handler.available_caps.get("sasl").unwrap();
        assert_eq!(sasl_cap.value, Some("PLAIN,EXTERNAL".to_string()));
        
        let sts_cap = handler.available_caps.get("sts").unwrap();
        assert_eq!(sts_cap.value, Some("duration=31536000,port=6697,preload".to_string()));
    }

    // Security validation tests
    #[test]
    fn test_invalid_capability_name_rejection() {
        let mut handler = CapabilityHandler::new();
        
        let params = vec!["nick".to_string(), "LS".to_string(), "invalid name=value".to_string()];
        let result = handler.handle_cap_ls(&params);
        
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_malicious_capability_name() {
        let mut handler = CapabilityHandler::new();
        
        let params = vec!["nick".to_string(), "LS".to_string(), "../../etc/passwd=value".to_string()];
        let result = handler.handle_cap_ls(&params);
        
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    // STS expiration tests
    #[test]
    fn test_sts_policy_expiration() {
        let mut handler = CapabilityHandler::new();
        
        // Set a policy that expires immediately
        handler.handle_sts_policy("irc.example.com", "duration=1").unwrap();
        
        // Should still be valid immediately
        assert_eq!(handler.should_upgrade_to_tls("irc.example.com"), Some(6697));
        
        // Wait for expiration (in practice, would need to mock time)
        // For now, we can't easily test actual expiration without time mocking
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_capability_name_validation_properties(
            name in "[a-zA-Z0-9._/-]{1,64}"
        ) {
            let handler = CapabilityHandler::new();
            
            // Names with only valid characters and reasonable length should be valid
            // unless they start with '-' or have invalid path structure
            let expected = !name.starts_with('-') && 
                          !name.contains("//") &&
                          (name.matches('/').count() <= 1);
            
            // Additional domain validation for vendor-specific caps
            let expected = if name.contains('/') {
                let parts: Vec<&str> = name.split('/').collect();
                expected && parts.len() == 2 && 
                (parts[0].ends_with(".com") || parts[0].ends_with(".org") || 
                 parts[0].ends_with(".net") || parts[0].ends_with(".chat") || 
                 parts[0].ends_with(".in") || !parts[0].contains('.'))
            } else {
                expected
            };
            
            prop_assert_eq!(handler.is_valid_capability_name(&name), expected);
        }

        #[test]
        fn test_sts_duration_parsing(duration in 1u64..=31536000u64) {
            let mut handler = CapabilityHandler::new();
            let policy_str = format!("duration={}", duration);
            
            let result = handler.handle_sts_policy("test.server", &policy_str);
            prop_assert!(result.is_ok());
            
            let policy = handler.sts_policies.get("test.server").unwrap();
            prop_assert_eq!(policy.duration.as_secs(), duration);
        }
    }

    // Integration tests
    #[test]
    fn test_full_capability_negotiation_flow() {
        let mut handler = CapabilityHandler::new();
        
        // 1. Server sends CAP LS
        let params = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN,EXTERNAL message-tags".to_string()];
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(!complete);
        
        let params = vec!["nick".to_string(), "LS".to_string(), "server-time batch".to_string()];
        let complete = handler.handle_cap_ls(&params).unwrap();
        assert!(complete);
        
        // 2. Client requests capabilities
        let caps_to_request = handler.get_capabilities_to_request();
        assert!(!caps_to_request.is_empty());
        
        // 3. Server acknowledges capabilities
        handler.handle_cap_ack(&caps_to_request).unwrap();
        
        // 4. Verify capabilities are enabled
        for cap in &caps_to_request {
            assert!(handler.is_capability_enabled(cap));
        }
        
        // 5. Complete negotiation
        handler.set_negotiation_complete();
        assert!(handler.is_negotiation_complete());
    }

    #[test]
    fn test_capability_negotiation_with_rejection() {
        let mut handler = CapabilityHandler::new();
        
        // Server offers capabilities
        let params = vec!["nick".to_string(), "LS".to_string(), "sasl=PLAIN message-tags server-time".to_string()];
        handler.handle_cap_ls(&params).unwrap();
        
        let caps_to_request = handler.get_capabilities_to_request();
        
        // Server rejects some capabilities
        let rejected = vec!["message-tags".to_string()];
        let accepted: Vec<String> = caps_to_request.iter()
            .filter(|cap| !rejected.contains(cap))
            .cloned()
            .collect();
        
        handler.handle_cap_nak(&rejected).unwrap();
        handler.handle_cap_ack(&accepted).unwrap();
        
        // Verify state
        assert!(!handler.is_capability_enabled("message-tags"));
        for cap in &accepted {
            assert!(handler.is_capability_enabled(cap));
        }
    }

    // Error handling tests
    #[test]
    fn test_malformed_capability_parsing() {
        let mut handler = CapabilityHandler::new();
        
        // Test various malformed inputs
        let malformed_inputs = vec![
            "cap=value=extra",
            "=value",
            "cap==value",
            "cap=",
        ];
        
        for input in malformed_inputs {
            let params = vec!["nick".to_string(), "LS".to_string(), input.to_string()];
            // Should not crash, might succeed or fail depending on specific format
            let _ = handler.handle_cap_ls(&params);
        }
    }

    // Stress tests
    #[test]
    fn test_large_capability_list() {
        let mut handler = CapabilityHandler::new();
        
        // Create a large list of capabilities
        let mut caps = Vec::new();
        for i in 0..100 {
            caps.push(format!("cap{i}=value{i}"));
        }
        let cap_string = caps.join(" ");
        
        let params = vec!["nick".to_string(), "LS".to_string(), cap_string];
        let result = handler.handle_cap_ls(&params);
        assert!(result.is_ok());
        
        assert_eq!(handler.available_caps.len(), 100);
    }

    #[test]
    fn test_capability_name_edge_cases() {
        let handler = CapabilityHandler::new();
        
        // Test edge cases for capability name validation
        assert!(handler.is_valid_capability_name("a"));
        assert!(handler.is_valid_capability_name(&"a".repeat(64)));
        assert!(!handler.is_valid_capability_name(&"a".repeat(65)));
        assert!(!handler.is_valid_capability_name(""));
        assert!(handler.is_valid_capability_name("example.com/feature"));
        assert!(!handler.is_valid_capability_name("invalid.domain/feature"));
    }
}