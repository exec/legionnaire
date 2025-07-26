use crate::error::{IronError, Result};
use std::collections::HashMap;
use std::str::FromStr;

const MAX_MESSAGE_LENGTH: usize = 512;
const MAX_TAG_LENGTH: usize = 8191;
const MAX_PARAMS: usize = 15;

#[derive(Debug, Clone, PartialEq)]
pub struct IrcMessage {
    pub tags: HashMap<String, Option<String>>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl IrcMessage {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: command.into(),
            params: Vec::new(),
        }
    }

    pub fn with_params(mut self, params: Vec<String>) -> Self {
        self.params = params;
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_tag(mut self, key: impl Into<String>, value: Option<String>) -> Self {
        self.tags.insert(key.into(), value);
        self
    }

    fn validate_security(&self) -> Result<()> {
        if self.command.len() > 32 {
            return Err(IronError::SecurityViolation(
                "Command too long".to_string()
            ));
        }

        if self.params.len() > MAX_PARAMS {
            return Err(IronError::SecurityViolation(
                "Too many parameters".to_string()
            ));
        }

        for param in &self.params {
            if param.len() > MAX_MESSAGE_LENGTH {
                return Err(IronError::SecurityViolation(
                    "Parameter too long".to_string()
                ));
            }
            
            if param.contains('\0') || param.contains('\r') || param.contains('\n') {
                return Err(IronError::SecurityViolation(
                    "Invalid characters in parameter".to_string()
                ));
            }
        }

        if let Some(prefix) = &self.prefix {
            if prefix.len() > 255 || prefix.contains('\0') || prefix.contains(' ') {
                return Err(IronError::SecurityViolation(
                    "Invalid prefix".to_string()
                ));
            }
        }

        let total_tag_length: usize = self.tags.iter()
            .map(|(k, v)| k.len() + v.as_ref().map_or(0, |s| s.len()) + 2)
            .sum();
        
        if total_tag_length > MAX_TAG_LENGTH {
            return Err(IronError::SecurityViolation(
                "Tags too long".to_string()
            ));
        }

        Ok(())
    }
}

impl FromStr for IrcMessage {
    type Err = IronError;

    fn from_str(line: &str) -> Result<Self> {
        if line.len() > MAX_MESSAGE_LENGTH + MAX_TAG_LENGTH {
            return Err(IronError::SecurityViolation(
                "Message too long".to_string()
            ));
        }

        let line = line.trim_end_matches("\r\n");
        let mut message = IrcMessage::new("");
        let mut remaining = line;

        if remaining.starts_with('@') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| IronError::Parse("No space after tags".to_string()))?;
            
            let tag_str = &remaining[1..space_pos];
            remaining = &remaining[space_pos + 1..];

            for tag in tag_str.split(';') {
                if tag.is_empty() {
                    continue;
                }

                let (key, value) = if let Some(eq_pos) = tag.find('=') {
                    let key = &tag[..eq_pos];
                    let value_str = &tag[eq_pos + 1..];
                    let value = if value_str.is_empty() {
                        None
                    } else {
                        Some(unescape_tag_value(value_str))
                    };
                    (key, value)
                } else {
                    (tag, None)
                };

                if !is_valid_tag_key(key) {
                    return Err(IronError::SecurityViolation(
                        format!("Invalid tag key: {}", key)
                    ));
                }

                message.tags.insert(key.to_string(), value);
            }
        }

        if remaining.starts_with(':') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| IronError::Parse("No space after prefix".to_string()))?;
            
            message.prefix = Some(remaining[1..space_pos].to_string());
            remaining = &remaining[space_pos + 1..];
        }

        let mut parts: Vec<&str> = remaining.splitn(15, ' ').collect();
        
        if parts.is_empty() {
            return Err(IronError::Parse("No command found".to_string()));
        }

        message.command = parts.remove(0).to_uppercase();

        if !is_valid_command(&message.command) {
            return Err(IronError::SecurityViolation(
                format!("Invalid command: {}", message.command)
            ));
        }

        for (i, part) in parts.iter().enumerate() {
            if part.starts_with(':') && i > 0 {
                let trailing = parts[i..].join(" ");
                message.params.push(trailing[1..].to_string());
                break;
            } else {
                message.params.push(part.to_string());
            }
        }

        message.validate_security()?;
        Ok(message)
    }
}

impl std::fmt::Display for IrcMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.tags.is_empty() {
            write!(f, "@")?;
            let mut first = true;
            for (key, value) in &self.tags {
                if !first {
                    write!(f, ";")?;
                }
                first = false;
                write!(f, "{}", key)?;
                if let Some(val) = value {
                    write!(f, "={}", escape_tag_value(val))?;
                }
            }
            write!(f, " ")?;
        }

        if let Some(prefix) = &self.prefix {
            write!(f, ":{} ", prefix)?;
        }

        write!(f, "{}", self.command)?;

        for (i, param) in self.params.iter().enumerate() {
            if i == self.params.len() - 1 && (param.contains(' ') || param.starts_with(':')) {
                write!(f, " :{}", param)?;
            } else {
                write!(f, " {}", param)?;
            }
        }

        write!(f, "\r\n")
    }
}

fn unescape_tag_value(value: &str) -> String {
    value
        .replace("\\:", ";")
        .replace("\\s", " ")
        .replace("\\\\", "\\")
        .replace("\\r", "\r")
        .replace("\\n", "\n")
}

fn escape_tag_value(value: &str) -> String {
    value
        .replace("\\", "\\\\")
        .replace(";", "\\:")
        .replace(" ", "\\s")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
}

fn is_valid_tag_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }

    key.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        c == '-' || c == '/' || c == '.' || c == '_'
    })
}

fn is_valid_command(command: &str) -> bool {
    if command.is_empty() || command.len() > 32 {
        return false;
    }

    command.chars().all(|c| c.is_ascii_alphanumeric()) ||
    command.chars().all(|c| c.is_ascii_digit()) && command.len() == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_message_parsing() {
        let msg = "PRIVMSG #channel :Hello world".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello world"]);
    }

    #[test]
    fn test_message_with_tags() {
        let msg = "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert!(msg.tags.contains_key("time"));
        assert_eq!(msg.command, "PRIVMSG");
    }

    #[test]
    fn test_security_validation() {
        let long_command = "A".repeat(100);
        let result = format!("{} #channel :test", long_command).parse::<IrcMessage>();
        assert!(result.is_err());
    }
}