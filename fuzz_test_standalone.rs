// Standalone fuzzing test for IRC message parsing
// This can be run independently to test the fuzzing infrastructure

use std::str::FromStr;
use std::collections::HashMap;

// Simplified version of the core parsing logic for testing
#[derive(Debug, Clone, PartialEq)]
pub struct TestIrcMessage {
    pub tags: HashMap<String, Option<String>>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

#[derive(Debug)]
pub enum TestError {
    Parse(String),
    SecurityViolation(String),
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestError::Parse(msg) => write!(f, "Parse error: {}", msg),
            TestError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
        }
    }
}

impl std::error::Error for TestError {}

const MAX_MESSAGE_LENGTH: usize = 512;
const MAX_TAG_LENGTH: usize = 8191;
const MAX_PARAMS: usize = 15;

impl FromStr for TestIrcMessage {
    type Err = TestError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        if line.len() > MAX_MESSAGE_LENGTH + MAX_TAG_LENGTH {
            return Err(TestError::SecurityViolation(
                "Message too long".to_string()
            ));
        }

        let line = line.trim_end_matches("\r\n");
        let mut message = TestIrcMessage {
            tags: HashMap::new(),
            prefix: None,
            command: String::new(),
            params: Vec::new(),
        };
        let mut remaining = line;

        // Parse tags
        if remaining.starts_with('@') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| TestError::Parse("No space after tags".to_string()))?;
            
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
                    return Err(TestError::SecurityViolation(
                        format!("Invalid tag key: {}", key)
                    ));
                }

                message.tags.insert(key.to_string(), value);
            }
        }

        // Parse prefix
        if remaining.starts_with(':') {
            let space_pos = remaining.find(' ')
                .ok_or_else(|| TestError::Parse("No space after prefix".to_string()))?;
            
            message.prefix = Some(remaining[1..space_pos].to_string());
            remaining = &remaining[space_pos + 1..];
        }

        // Parse command and parameters
        let mut parts: Vec<&str> = remaining.splitn(15, ' ').collect();
        
        if parts.is_empty() {
            return Err(TestError::Parse("No command found".to_string()));
        }

        message.command = parts.remove(0).to_uppercase();

        if !is_valid_command(&message.command) {
            return Err(TestError::SecurityViolation(
                format!("Invalid command: {}", message.command)
            ));
        }

        // Parse parameters
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with(':') && i > 0 {
                let trailing = parts[i..].join(" ");
                message.params.push(trailing[1..].to_string());
                break;
            } else {
                message.params.push(part.to_string());
            }
        }

        // Validate security
        validate_security(&message)?;
        Ok(message)
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
    (command.chars().all(|c| c.is_ascii_digit()) && command.len() == 3)
}

fn validate_security(message: &TestIrcMessage) -> Result<(), TestError> {
    if message.command.len() > 32 {
        return Err(TestError::SecurityViolation(
            "Command too long".to_string()
        ));
    }

    if message.params.len() > MAX_PARAMS {
        return Err(TestError::SecurityViolation(
            "Too many parameters".to_string()
        ));
    }

    for param in &message.params {
        if param.len() > MAX_MESSAGE_LENGTH {
            return Err(TestError::SecurityViolation(
                "Parameter too long".to_string()
            ));
        }
        
        if param.contains('\0') || param.contains('\r') || param.contains('\n') {
            return Err(TestError::SecurityViolation(
                "Invalid characters in parameter".to_string()
            ));
        }
    }

    if let Some(prefix) = &message.prefix {
        if prefix.len() > 255 || prefix.contains('\0') || prefix.contains(' ') {
            return Err(TestError::SecurityViolation(
                "Invalid prefix".to_string()
            ));
        }
    }

    let total_tag_length: usize = message.tags.iter()
        .map(|(k, v)| k.len() + v.as_ref().map_or(0, |s| s.len()) + 2)
        .sum();
    
    if total_tag_length > MAX_TAG_LENGTH {
        return Err(TestError::SecurityViolation(
            "Tags too long".to_string()
        ));
    }

    Ok(())
}

// Fuzzing function
pub fn fuzz_message_parsing(data: &[u8]) {
    if let Ok(input) = std::str::from_utf8(data) {
        // Test basic parsing
        let _ = TestIrcMessage::from_str(input);
        
        // Test with various line endings
        let input_crlf = format!("{}\r\n", input);
        let _ = TestIrcMessage::from_str(&input_crlf);
        
        let input_lf = format!("{}\n", input);
        let _ = TestIrcMessage::from_str(&input_lf);
        
        // Test with extra whitespace
        let input_spaces = format!("  {}  ", input);
        let _ = TestIrcMessage::from_str(&input_spaces);
    }
    
    // Also test with potentially malformed UTF-8
    let lossy_input = String::from_utf8_lossy(data);
    let _ = TestIrcMessage::from_str(&lossy_input);
}

fn main() {
    println!("IRC Message Parsing Fuzzer Test");
    
    // Test some basic cases
    let long_a = "A".repeat(1000);
    let long_at = "@".repeat(10000);
    let test_cases = [
        "PRIVMSG #channel :Hello world",
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Tagged message",
        ":nick!user@host.com PRIVMSG #channel :Message with prefix",
        "@id=123;time=2023-01-01T00:00:00.000Z :nick!user@host.com PRIVMSG #channel :Complex message",
        "JOIN #channel",
        "001 nick :Welcome message",
        "",
        long_a.as_str(),
        long_at.as_str(),
    ];
    
    for (i, test_case) in test_cases.iter().enumerate() {
        println!("Testing case {}: {:?}", i + 1, test_case);
        fuzz_message_parsing(test_case.as_bytes());
        println!("  -> No crash");
    }
    
    println!("\nBasic fuzzing test completed successfully!");
    println!("To run comprehensive fuzzing:");
    println!("1. Set up cargo-fuzz with: cargo install cargo-fuzz");
    println!("2. Switch to nightly: rustup default nightly");
    println!("3. Run: ./fuzz_runner.sh");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parsing() {
        let msg = TestIrcMessage::from_str("PRIVMSG #channel :Hello world").unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#channel", "Hello world"]);
        assert!(msg.tags.is_empty());
        assert!(msg.prefix.is_none());
    }

    #[test]
    fn test_tagged_message() {
        let msg = TestIrcMessage::from_str("@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello").unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert!(msg.tags.contains_key("time"));
    }

    #[test]
    fn test_security_limits() {
        let long_command = "A".repeat(100);
        let result = TestIrcMessage::from_str(&format!("{} #channel :test", long_command));
        assert!(result.is_err());
    }

    #[test]
    fn test_fuzzing_function() {
        // Test that the fuzzing function doesn't crash on various inputs
        fuzz_message_parsing(b"PRIVMSG #test :hello");
        fuzz_message_parsing(b"@tag=value NOTICE * :test");
        fuzz_message_parsing(b"\x00\x01\x02\x03\x04");
        fuzz_message_parsing(&[255, 254, 253, 252]);
    }
}