use crate::error::{IronError, Result};
use std::collections::HashMap;
use std::time::SystemTime;
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

    pub fn raw(data: &str) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: "RAW".to_string(),
            params: vec![data.to_string()],
        }
    }

    /// Extract server timestamp from message tags, fallback to current time
    pub fn get_timestamp(&self) -> SystemTime {
        if let Some(Some(time_str)) = self.tags.get("time") {
            // Parse ISO 8601 timestamp from server-time capability
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
                return SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp() as u64);
            }
        }
        SystemTime::now()
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
    use proptest::prelude::*;

    // Basic parsing tests
    #[test]
    fn test_basic_message_parsing() {
        let msg = "PRIVMSG #channel :Hello world".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello world"]);
        assert!(msg.tags.is_empty());
        assert!(msg.prefix.is_none());
    }

    #[test]
    fn test_message_with_tags() {
        let msg = "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert!(msg.tags.contains_key("time"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello"]);
    }

    #[test]
    fn test_message_with_prefix() {
        let msg = ":nick!user@host PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.prefix, Some("nick!user@host".to_string()));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello"]);
    }

    #[test]
    fn test_message_with_tags_and_prefix() {
        let msg = "@id=123;time=2023-01-01T00:00:00.000Z :nick!user@host PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.tags.len(), 2);
        assert!(msg.tags.contains_key("id"));
        assert!(msg.tags.contains_key("time"));
        assert_eq!(msg.prefix, Some("nick!user@host".to_string()));
        assert_eq!(msg.command, "PRIVMSG");
    }

    // Edge case tests
    #[test]
    fn test_empty_message() {
        let result = "".parse::<IrcMessage>();
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_message() {
        let result = "   \t  ".parse::<IrcMessage>();
        assert!(result.is_err());
    }

    #[test]
    fn test_command_only() {
        let msg = "PING".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "PING");
        assert!(msg.params.is_empty());
    }

    #[test]
    fn test_numeric_command() {
        let msg = "001 nick :Welcome".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "001");
        assert_eq!(msg.params, vec!["nick", "Welcome"]);
    }

    #[test]
    fn test_long_trailing_parameter() {
        let long_msg = "a".repeat(400);
        let input = format!("PRIVMSG #channel :{}", long_msg);
        let msg = input.parse::<IrcMessage>().unwrap();
        assert_eq!(msg.params[1], long_msg);
    }

    #[test]
    fn test_multiple_spaces_between_params() {
        let msg = "PRIVMSG    #channel     :Hello    world".parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello    world"]);
    }

    #[test]
    fn test_empty_tag_value() {
        let msg = "@tag1=;tag2=value PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.tags.get("tag1"), Some(&None));
        assert_eq!(msg.tags.get("tag2"), Some(&Some("value".to_string())));
    }

    #[test]
    fn test_tag_without_value() {
        let msg = "@tag1;tag2=value PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.tags.get("tag1"), Some(&None));
        assert_eq!(msg.tags.get("tag2"), Some(&Some("value".to_string())));
    }

    #[test]
    fn test_tag_value_escaping() {
        let msg = "@msg=hello\\sworld\\ntest\\r\\\\end PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.tags.get("msg"), Some(&Some("hello world\ntest\r\\end".to_string())));
    }

    #[test]
    fn test_semicolon_in_tag_value() {
        let msg = "@msg=hello\\:world PRIVMSG #channel :Hello"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.tags.get("msg"), Some(&Some("hello;world".to_string())));
    }

    #[test]
    fn test_trailing_parameter_with_colon() {
        let msg = "PRIVMSG #channel ::This starts with colon"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.params, vec!["#channel", ":This starts with colon"]);
    }

    #[test]
    fn test_trailing_parameter_with_spaces() {
        let msg = "PRIVMSG #channel :Hello world with spaces"
            .parse::<IrcMessage>().unwrap();
        assert_eq!(msg.params, vec!["#channel", "Hello world with spaces"]);
    }

    #[test]
    fn test_max_parameters() {
        // Per RFC 1459, splitn(15) includes command, so we get max 14 params
        // The 14th parameter will include all remaining text
        let params = (0..13).map(|i| format!("param{}", i)).collect::<Vec<_>>();
        let input = format!("COMMAND {} param13 param14", params.join(" "));
        let msg = input.parse::<IrcMessage>().unwrap();
        assert_eq!(msg.params.len(), 14);
        assert_eq!(msg.params[13], "param13 param14");
    }

    // Security validation tests
    #[test]
    fn test_security_command_too_long() {
        let long_command = "A".repeat(100);
        let result = format!("{} #channel :test", long_command).parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_too_many_parameters() {
        let params = (0..20).map(|i| format!("param{}", i)).collect::<Vec<_>>();
        let input = format!("COMMAND {}", params.join(" "));
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_parameter_too_long() {
        let long_param = "a".repeat(600);
        let input = format!("PRIVMSG {} :test", long_param);
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_null_byte_in_parameter() {
        let input = "PRIVMSG #channel\0 :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_carriage_return_in_parameter() {
        let input = "PRIVMSG #channel\r :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_newline_in_parameter() {
        let input = "PRIVMSG #channel\n :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_invalid_prefix() {
        let input = ":invalid\0prefix PRIVMSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_prefix_too_long() {
        let long_prefix = "a".repeat(300);
        let input = format!(":{} PRIVMSG #channel :test", long_prefix);
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_prefix_with_space() {
        let input = ":nick user@host PRIVMSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_tags_too_long() {
        let long_value = "a".repeat(8000);
        let input = format!("@tag={} PRIVMSG #channel :test", long_value);
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_message_too_long() {
        let long_message = "a".repeat(10000);
        let result = long_message.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_invalid_tag_key() {
        let input = "@invalid tag=value PRIVMSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_tag_key_too_long() {
        let long_tag = "a".repeat(100);
        let input = format!("@{}=value PRIVMSG #channel :test", long_tag);
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    #[test]
    fn test_security_invalid_command_chars() {
        let input = "PRIV@MSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::SecurityViolation(_))));
    }

    // Parse error tests
    #[test]
    fn test_parse_error_no_space_after_tags() {
        let input = "@tag=valuePRIVMSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    #[test]
    fn test_parse_error_no_space_after_prefix() {
        let input = ":nick!user@hostPRIVMSG #channel :test";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    #[test]
    fn test_parse_error_no_command() {
        let input = ":nick!user@host  ";
        let result = input.parse::<IrcMessage>();
        assert!(matches!(result, Err(IronError::Parse(_))));
    }

    // Valid tag key tests
    #[test]
    fn test_message_tag_key_validation() {
        let long_tag = "a".repeat(65);
        let test_cases = vec![
            ("valid-tag", true),
            ("valid.tag", true),
            ("valid_tag", true),
            ("valid/tag", true),
            ("example.com/tag", true),
            ("123abc", true),
            ("", false),
            ("invalid tag", false),
            ("invalid@tag", false),
            ("invalid#tag", false),
            (long_tag.as_str(), false),
        ];
        
        for (key, expected) in test_cases {
            assert_eq!(is_valid_tag_key(key), expected, "Failed for key: {}", key);
        }
    }

    // Valid command tests
    #[test]
    fn test_message_command_validation() {
        let long_command = "A".repeat(33);
        let test_cases = vec![
            ("PRIVMSG", true),
            ("001", true),
            ("999", true),
            ("JOIN", true),
            ("", false),
            ("INVALID@CMD", false),
            ("12", false),
            ("1234", false),
            (long_command.as_str(), false),
        ];
        
        for (command, expected) in test_cases {
            assert_eq!(is_valid_command(command), expected, "Failed for command: {}", command);
        }
    }

    // Message formatting tests
    #[test]
    fn test_message_formatting_basic() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
        let formatted = msg.to_string();
        assert_eq!(formatted, "PRIVMSG #channel :Hello world\r\n");
    }

    #[test]
    fn test_message_formatting_with_tags() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_tag("id", Some("123".to_string()))
            .with_tag("time", Some("2023-01-01T00:00:00.000Z".to_string()))
            .with_params(vec!["#channel".to_string(), "Hello".to_string()]);
        let formatted = msg.to_string();
        assert!(formatted.starts_with('@'));
        assert!(formatted.contains("id=123"));
        assert!(formatted.contains("time=2023-01-01T00:00:00.000Z"));
        assert!(formatted.ends_with("PRIVMSG #channel :Hello\r\n"));
    }

    #[test]
    fn test_message_formatting_with_prefix() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_prefix("nick!user@host")
            .with_params(vec!["#channel".to_string(), "Hello".to_string()]);
        let formatted = msg.to_string();
        assert_eq!(formatted, ":nick!user@host PRIVMSG #channel :Hello\r\n");
    }

    #[test]
    fn test_message_formatting_tag_escaping() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_tag("msg", Some("hello world\ntest\r\\end;more".to_string()))
            .with_params(vec!["#channel".to_string(), "Hello".to_string()]);
        let formatted = msg.to_string();
        assert!(formatted.contains("msg=hello\\sworld\\ntest\\r\\\\end\\:more"));
    }

    #[test]
    fn test_message_formatting_trailing_param_with_space() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
        let formatted = msg.to_string();
        assert!(formatted.contains(" :Hello world"));
    }

    #[test]
    fn test_message_formatting_trailing_param_with_colon() {
        let msg = IrcMessage::new("PRIVMSG")
            .with_params(vec!["#channel".to_string(), ":Hello".to_string()]);
        let formatted = msg.to_string();
        assert!(formatted.contains(" ::Hello"));
    }

    // Round-trip tests
    #[test]
    fn test_round_trip_basic() {
        let original = "PRIVMSG #channel :Hello world";
        let msg = original.parse::<IrcMessage>().unwrap();
        let formatted = msg.to_string();
        let reparsed = formatted.parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, reparsed.command);
        assert_eq!(msg.params, reparsed.params);
    }

    #[test]
    fn test_round_trip_with_tags() {
        let original = "@id=123;time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello";
        let msg = original.parse::<IrcMessage>().unwrap();
        let formatted = msg.to_string();
        let reparsed = formatted.parse::<IrcMessage>().unwrap();
        assert_eq!(msg.command, reparsed.command);
        assert_eq!(msg.params, reparsed.params);
        assert_eq!(msg.tags.len(), reparsed.tags.len());
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_valid_commands_parse_successfully(
            command in "[A-Z][A-Z0-9]{0,30}|[0-9]{3}"
        ) {
            let input = format!("{} #channel :test", command);
            let result = input.parse::<IrcMessage>();
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().command, command);
        }

        #[test]
        fn test_valid_tag_keys_parse_successfully(
            key in "[a-zA-Z0-9._/-]{1,64}"
        ) {
            // Filter out invalid patterns
            prop_assume!(is_valid_tag_key(&key));
            
            let input = format!("@{}=value PRIVMSG #channel :test", key);
            let result = input.parse::<IrcMessage>();
            prop_assert!(result.is_ok());
            prop_assert!(result.unwrap().tags.contains_key(&key));
        }

        #[test]
        fn test_parameter_count_within_limits(
            param_count in 0..15usize
        ) {
            let params: Vec<String> = (0..param_count)
                .map(|i| format!("param{}", i))
                .collect();
            let input = format!("COMMAND {}", params.join(" "));
            let result = input.parse::<IrcMessage>();
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().params.len(), param_count);
        }

        #[test]
        fn test_message_length_validation(
            msg_len in 0..=600usize
        ) {
            let content = "a".repeat(msg_len);
            let input = format!("PRIVMSG #channel :{}", content);
            let result = input.parse::<IrcMessage>();
            
            if msg_len <= MAX_MESSAGE_LENGTH {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }
    }

    // Benchmark preparation tests
    #[test]
    fn test_parsing_performance_simple() {
        let input = "PRIVMSG #channel :Hello world";
        for _ in 0..1000 {
            let _ = input.parse::<IrcMessage>().unwrap();
        }
    }

    #[test]
    fn test_parsing_performance_complex() {
        let input = "@id=123;time=2023-01-01T00:00:00.000Z;account=user :nick!user@host.example.com PRIVMSG #channel :Hello world with a longer message";
        for _ in 0..1000 {
            let _ = input.parse::<IrcMessage>().unwrap();
        }
    }
}