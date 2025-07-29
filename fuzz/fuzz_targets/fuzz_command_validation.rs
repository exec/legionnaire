#![no_main]

use libfuzzer_sys::fuzz_target;
use ironchat::message::IrcMessage;
use std::str::FromStr;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct CommandTestData {
    command: String,
    params: Vec<String>,
    prefix: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Test structured command data
    if let Ok(cmd_data) = CommandTestData::arbitrary(&mut u) {
        let mut message_parts = Vec::new();
        
        if let Some(prefix) = cmd_data.prefix {
            message_parts.push(format!(":{}", prefix));
        }
        
        message_parts.push(cmd_data.command);
        message_parts.extend(cmd_data.params);
        
        let test_message = message_parts.join(" ");
        let _ = IrcMessage::from_str(&test_message);
    }
    
    // Test raw command fuzzing
    if let Ok(input) = std::str::from_utf8(data) {
        // Test as command directly
        let simple_cmd = format!("{} #channel :message", input);
        let _ = IrcMessage::from_str(&simple_cmd);
        
        // Test with prefix
        let prefixed_cmd = format!(":nick!user@host {} param1 param2", input);
        let _ = IrcMessage::from_str(&prefixed_cmd);
        
        // Test numeric commands (should be 3 digits)
        if input.chars().all(|c| c.is_ascii_digit()) {
            let numeric_cmd = format!(":{} {} target :numeric response", 
                                    "server.example.com", input);
            let _ = IrcMessage::from_str(&numeric_cmd);
        }
        
        // Test very long commands (should trigger security validation)
        let long_cmd = format!("{} param", input.repeat(10));
        let _ = IrcMessage::from_str(&long_cmd);
        
        // Test commands with special characters
        let special_cmd = format!("{}{}{}! param :trailing", input, "\x00", "\r\n");
        let _ = IrcMessage::from_str(&special_cmd);
    }
    
    // Test edge cases with zero-length and single character commands
    let _ = IrcMessage::from_str("");
    let _ = IrcMessage::from_str(" ");
    let _ = IrcMessage::from_str("A");
    let _ = IrcMessage::from_str("ABC");
    
    // Test boundary conditions for command length (32 char limit)
    let boundary_cmd = "A".repeat(32);
    let _ = IrcMessage::from_str(&boundary_cmd);
    
    let too_long_cmd = "A".repeat(33);
    let _ = IrcMessage::from_str(&too_long_cmd);
});