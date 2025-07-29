#![no_main]

use libfuzzer_sys::fuzz_target;
use ironchat::message::IrcMessage;
use std::str::FromStr;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct ParameterTestData {
    params: Vec<String>,
    trailing: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Test structured parameter data
    if let Ok(param_data) = ParameterTestData::arbitrary(&mut u) {
        let mut message = String::from("PRIVMSG");
        
        for param in &param_data.params {
            message.push(' ');
            message.push_str(param);
        }
        
        if let Some(trailing) = param_data.trailing {
            message.push_str(" :");
            message.push_str(&trailing);
        }
        
        let _ = IrcMessage::from_str(&message);
    }
    
    // Test raw parameter fuzzing
    if let Ok(input) = std::str::from_utf8(data) {
        // Test maximum parameters (15 limit)
        let mut many_params = String::from("CMD");
        for i in 0..20 {
            many_params.push_str(&format!(" param{}", i));
        }
        many_params.push_str(&format!(" :{}", input));
        let _ = IrcMessage::from_str(&many_params);
        
        // Test trailing parameter edge cases
        let trailing_tests = [
            format!("PRIVMSG #test :{}", input),
            format!("PRIVMSG #test : {}", input),  // space after colon
            format!("PRIVMSG #test :{} {}", input, input),  // spaces in trailing
            format!("PRIVMSG #test :{}", input.repeat(10)),  // long trailing
        ];
        
        for test in trailing_tests {
            let _ = IrcMessage::from_str(&test);
        }
        
        // Test parameters with special characters
        let special_chars = ["\r", "\n", "\0", "\x01", "\x7F"];
        for &special in &special_chars {
            let special_param = format!("PRIVMSG {} :message", special);
            let _ = IrcMessage::from_str(&special_param);
            
            let special_trailing = format!("PRIVMSG #test :{}", special);
            let _ = IrcMessage::from_str(&special_trailing);
        }
        
        // Test very long parameters
        let long_param = input.repeat(100);
        let long_param_msg = format!("PRIVMSG {} :test", long_param);
        let _ = IrcMessage::from_str(&long_param_msg);
        
        // Test parameter boundary conditions
        let boundary_param = "A".repeat(512);  // MAX_MESSAGE_LENGTH
        let boundary_msg = format!("PRIVMSG {} :test", boundary_param);
        let _ = IrcMessage::from_str(&boundary_msg);
        
        // Test colon handling edge cases
        let colon_tests = [
            format!("PRIVMSG :{}", input),  // trailing starts immediately
            format!("PRIVMSG : {}", input),  // space after colon
            format!("PRIVMSG ::{}", input),  // double colon
            format!("PRIVMSG #test: {}", input),  // colon in parameter
            format!("PRIVMSG #test {}: message", input),  // colon in middle param
        ];
        
        for test in colon_tests {
            let _ = IrcMessage::from_str(&test);
        }
        
        // Test empty parameters
        let empty_tests = [
            "PRIVMSG  #test :message",  // double space
            "PRIVMSG #test  :message",  // space before trailing
            "PRIVMSG #test :",  // empty trailing
            "PRIVMSG  :message",  // missing parameter
        ];
        
        for test in empty_tests {
            let _ = IrcMessage::from_str(test);
        }
    }
});