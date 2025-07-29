use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ironchat::message::IrcMessage;
use std::str::FromStr;

fn bench_message_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_parsing");
    
    // Simple messages
    let simple_messages = vec![
        "PING :server.example.com",
        "PONG :server.example.com",
        "JOIN #channel",
        "PART #channel",
        "QUIT :Goodbye",
        "PRIVMSG #channel :Hello world",
        "NOTICE #channel :Notice message",
        "MODE #channel +o nick",
        "KICK #channel nick :reason",
        "001 nick :Welcome to IRC",
        "353 nick = #channel :nick1 nick2 nick3",
        "366 nick #channel :End of NAMES list",
    ];
    
    for (i, message) in simple_messages.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("simple", i),
            message,
            |b, msg| {
                b.iter(|| {
                    black_box(msg.parse::<IrcMessage>().unwrap())
                })
            }
        );
    }
    
    // Complex messages with tags
    let complex_messages = vec![
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello",
        "@id=123;time=2023-01-01T00:00:00.000Z;account=user :nick!user@host PRIVMSG #channel :Message",
        "@batch=123;msgid=abc;time=2023-01-01T00:00:00.000Z :nick!user@host PRIVMSG #channel :Batch message",
        "@reply=456;+typing=active :nick!user@host PRIVMSG #channel :Reply message",
        "@label=789;+draft/reply=123 :nick!user@host PRIVMSG #channel :Labeled message",
    ];
    
    for (i, message) in complex_messages.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("complex", i),
            message,
            |b, msg| {
                b.iter(|| {
                    black_box(msg.parse::<IrcMessage>().unwrap())
                })
            }
        );
    }
    
    // Long messages
    let long_content = "a".repeat(400);
    let long_message = format!("PRIVMSG #channel :{}", long_content);
    
    group.bench_function("long_message", |b| {
        b.iter(|| {
            black_box(long_message.parse::<IrcMessage>().unwrap())
        })
    });
    
    // Messages with many parameters
    let many_params = (0..14).map(|i| format!("param{}", i)).collect::<Vec<_>>();
    let many_params_msg = format!("COMMAND {}", many_params.join(" "));
    
    group.bench_function("many_params", |b| {
        b.iter(|| {
            black_box(many_params_msg.parse::<IrcMessage>().unwrap())
        })
    });
    
    group.finish();
}

fn bench_message_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_formatting");
    
    // Simple message formatting
    let simple_msg = IrcMessage::new("PRIVMSG")
        .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
    
    group.bench_function("simple", |b| {
        b.iter(|| {
            black_box(simple_msg.to_string())
        })
    });
    
    // Complex message with tags and prefix
    let complex_msg = IrcMessage::new("PRIVMSG")
        .with_prefix("nick!user@host")
        .with_tag("time", Some("2023-01-01T00:00:00.000Z".to_string()))
        .with_tag("id", Some("123".to_string()))
        .with_tag("account", Some("user".to_string()))
        .with_params(vec!["#channel".to_string(), "Hello world".to_string()]);
    
    group.bench_function("complex", |b| {
        b.iter(|| {
            black_box(complex_msg.to_string())
        })
    });
    
    // Message with many tags
    let mut many_tags_msg = IrcMessage::new("PRIVMSG")
        .with_params(vec!["#channel".to_string(), "test".to_string()]);
    
    for i in 0..10 {
        many_tags_msg = many_tags_msg.with_tag(format!("tag{}", i), Some(format!("value{}", i)));
    }
    
    group.bench_function("many_tags", |b| {
        b.iter(|| {
            black_box(many_tags_msg.to_string())
        })
    });
    
    group.finish();
}

fn bench_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_trip");
    
    let test_messages = vec![
        "PRIVMSG #channel :Hello world",
        "@time=2023-01-01T00:00:00.000Z :nick!user@host PRIVMSG #channel :Hello",
        "353 nick = #channel :nick1 nick2 nick3 nick4 nick5",
    ];
    
    for (i, original) in test_messages.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("parse_format", i),
            original,
            |b, msg| {
                b.iter(|| {
                    let parsed = black_box(msg.parse::<IrcMessage>().unwrap());
                    black_box(parsed.to_string())
                })
            }
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_message_parsing, bench_message_formatting, bench_round_trip);
criterion_main!(benches);