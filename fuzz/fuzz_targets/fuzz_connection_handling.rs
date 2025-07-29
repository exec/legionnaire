#![no_main]

use libfuzzer_sys::fuzz_target;
use ironchat::message::IrcMessage;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    // Simulate connection-level message processing
    if let Ok(input) = std::str::from_utf8(data) {
        // Test messages that might come from a real IRC connection
        
        // Test line-by-line processing
        for line in input.lines() {
            let _ = IrcMessage::from_str(line);
            
            // Test with CRLF endings (standard IRC)
            let crlf_line = format!("{}\r\n", line);
            let _ = IrcMessage::from_str(&crlf_line);
        }
        
        // Test very long messages (simulate buffer overflow attempts)
        let long_message = input.repeat(100);
        let _ = IrcMessage::from_str(&long_message);
        
        // Test messages with embedded null bytes
        let null_message = format!("{}\x00{}", input, input);
        let _ = IrcMessage::from_str(&null_message);
        
        // Test fragmented messages (incomplete parsing)
        if input.len() > 1 {
            for i in 1..input.len() {
                let fragment = &input[..i];
                let _ = IrcMessage::from_str(fragment);
            }
        }
        
        // Test common IRC commands with fuzzy parameters
        let test_commands = [
            "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT", "NICK", 
            "USER", "PASS", "PING", "PONG", "KICK", "MODE",
            "TOPIC", "INVITE", "WHO", "WHOIS", "LIST"
        ];
        
        for cmd in &test_commands {
            let test_msg = format!("{} {}", cmd, input);
            let _ = IrcMessage::from_str(&test_msg);
            
            // With prefix
            let prefixed_msg = format!(":server.com {} {}", cmd, input);
            let _ = IrcMessage::from_str(&prefixed_msg);
            
            // With tags
            let tagged_msg = format!("@time=2023-01-01T00:00:00.000Z {} {}", cmd, input);
            let _ = IrcMessage::from_str(&tagged_msg);
        }
        
        // Test numeric responses
        for code in [1, 2, 3, 200, 300, 400, 401, 404, 500, 999] {
            let numeric_msg = format!(":{:03} {} {}", code, "target", input);
            let _ = IrcMessage::from_str(&numeric_msg);
        }
    }
    
    // Test binary data processing (should be rejected)
    let binary_msg = String::from_utf8_lossy(data);
    let _ = IrcMessage::from_str(&binary_msg);
    
    // Test ASCII validation boundaries
    for byte in data.iter().take(512) {
        let single_byte_msg = format!("TEST {}", *byte as char);
        let _ = IrcMessage::from_str(&single_byte_msg);
    }
});