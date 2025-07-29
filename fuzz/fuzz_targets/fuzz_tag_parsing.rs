#![no_main]

use libfuzzer_sys::fuzz_target;
use ironchat::message::IrcMessage;
use std::str::FromStr;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct TagData {
    key: String,
    value: Option<String>,
}

#[derive(Arbitrary, Debug)]
struct TagTestData {
    tags: Vec<TagData>,
    command: String,
    params: Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Generate structured tag data
    if let Ok(tag_data) = TagTestData::arbitrary(&mut u) {
        // Build IRC message with tags
        let mut message_parts = Vec::new();
        
        if !tag_data.tags.is_empty() {
            let mut tag_string = String::from("@");
            for (i, tag) in tag_data.tags.iter().enumerate() {
                if i > 0 {
                    tag_string.push(';');
                }
                tag_string.push_str(&tag.key);
                if let Some(ref value) = tag.value {
                    tag_string.push('=');
                    tag_string.push_str(value);
                }
            }
            message_parts.push(tag_string);
        }
        
        message_parts.push(tag_data.command);
        message_parts.extend(tag_data.params);
        
        let test_message = message_parts.join(" ");
        let _ = IrcMessage::from_str(&test_message);
    }
    
    // Test raw tag parsing with malformed data
    if let Ok(input) = std::str::from_utf8(data) {
        // Test with @ prefix
        let tag_message = format!("@{} PRIVMSG #test :hello", input);
        let _ = IrcMessage::from_str(&tag_message);
        
        // Test with various tag separators and escape sequences
        let complex_tags = format!("@{}={};key2=value2 NOTICE * :test", input);
        let _ = IrcMessage::from_str(&complex_tags);
        
        // Test edge cases with escaping
        let escaped_tags = format!("@key={}\\s\\:\\\\\\r\\n JOIN #channel", input);
        let _ = IrcMessage::from_str(&escaped_tags);
    }
});