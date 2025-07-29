#![no_main]

use libfuzzer_sys::fuzz_target;
use ironchat::message::IrcMessage;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to string, allowing for invalid UTF-8
    if let Ok(input) = std::str::from_utf8(data) {
        // Test basic parsing
        let _ = IrcMessage::from_str(input);
        
        // Test with various line endings
        let input_crlf = format!("{}\r\n", input);
        let _ = IrcMessage::from_str(&input_crlf);
        
        let input_lf = format!("{}\n", input);
        let _ = IrcMessage::from_str(&input_lf);
        
        // Test with extra whitespace
        let input_spaces = format!("  {}  ", input);
        let _ = IrcMessage::from_str(&input_spaces);
    }
    
    // Also test with potentially malformed UTF-8 by creating string lossy
    let lossy_input = String::from_utf8_lossy(data);
    let _ = IrcMessage::from_str(&lossy_input);
});