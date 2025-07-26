use crate::error::{IronError, Result};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

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
        
        debug!("Parsed capabilities: {:?}", self.available_caps.keys().collect::<Vec<_>>());
        
        Ok(!is_multiline)
    }

    pub fn handle_cap_ack(&mut self, caps: &[String]) -> Result<()> {
        for cap_name in caps {
            if let Some(cap) = self.available_caps.get(cap_name) {
                let mut enabled_cap = cap.clone();
                enabled_cap.enabled = true;
                self.enabled_caps.insert(cap_name.clone(), enabled_cap);
                info!("Capability enabled: {}", cap_name);
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
            warn!("Capability rejected: {}", cap);
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

        info!("New capabilities available: {:?}", new_requests);
        Ok(new_requests)
    }

    pub fn handle_cap_del(&mut self, caps: &[String]) -> Result<()> {
        for cap in caps {
            self.available_caps.remove(cap);
            self.enabled_caps.remove(cap);
            
            if matches!(cap.as_str(), "sasl" | "sts") {
                warn!("Lost critical security capability: {}", cap);
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
                warn!("SASL validation failed: {}", e);
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
        info!("Capability negotiation complete. Enabled: {:?}", 
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
            info!("STS policy revoked for {}", hostname);
            return Ok(());
        }
        
        let policy = StsPolicy {
            duration,
            port,
            preload,
            expires_at: SystemTime::now() + duration,
        };
        
        self.sts_policies.insert(hostname.to_string(), policy);
        info!("STS policy set for {}: {:?}", hostname, 
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
    fn test_sasl_mechanism_parsing() {
        let mut handler = CapabilityHandler::new();
        let params = vec!["*".to_string(), "LS".to_string(), "sasl=PLAIN,EXTERNAL".to_string()];
        
        handler.handle_cap_ls(&params).unwrap();
        handler.handle_cap_ack(&vec!["sasl".to_string()]).unwrap();
        
        let mechanisms = handler.get_sasl_mechanisms();
        assert_eq!(mechanisms, vec!["PLAIN", "EXTERNAL"]);
    }

    #[test]
    fn test_sts_policy_parsing() {
        let mut handler = CapabilityHandler::new();
        
        handler.handle_sts_policy("irc.example.com", "duration=300,port=6697,preload").unwrap();
        
        assert_eq!(handler.should_upgrade_to_tls("irc.example.com"), Some(6697));
    }
}