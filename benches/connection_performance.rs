use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ironchat::message::IrcMessage;
use std::time::Duration;

// Mock connection for benchmarking
struct MockConnection {
    data: Vec<u8>,
    pos: usize,
}

impl MockConnection {
    fn new(messages: &[&str]) -> Self {
        let data = messages.join("\n").into_bytes();
        Self { data, pos: 0 }
    }
    
    fn read_message(&mut self) -> Option<String> {
        if self.pos >= self.data.len() {
            return None;
        }
        
        let start = self.pos;
        let mut end = start;
        
        while end < self.data.len() && self.data[end] != b'\n' {
            end += 1;
        }
        
        if end >= self.data.len() {
            return None;
        }
        
        end += 1; // Include newline
        let line = String::from_utf8_lossy(&self.data[start..end]);
        self.pos = end;
        
        Some(line.trim().to_string())
    }
}

fn bench_message_reading(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_reading");
    
    // Prepare test data
    let simple_messages = vec![
        "PING :server.example.com",
        "PONG :server.example.com", 
        "PRIVMSG #channel :Hello",
        "JOIN #channel",
        "PART #channel",
    ];
    
    let complex_messages = vec![
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello",
        "@id=123;account=user :nick!user@host PRIVMSG #channel :Message",
        "@batch=abc;msgid=def PRIVMSG #channel :Batch message",
        "353 nick = #channel :nick1 nick2 nick3 nick4 nick5",
        "366 nick #channel :End of NAMES list",
    ];
    
    group.bench_function("simple_messages", |b| {
        b.iter(|| {
            let mut conn = MockConnection::new(&simple_messages);
            let mut count = 0;
            
            while let Some(line) = conn.read_message() {
                if let Ok(msg) = line.parse::<IrcMessage>() {
                    black_box(msg);
                    count += 1;
                }
            }
            
            black_box(count)
        })
    });
    
    group.bench_function("complex_messages", |b| {
        b.iter(|| {
            let mut conn = MockConnection::new(&complex_messages);
            let mut count = 0;
            
            while let Some(line) = conn.read_message() {
                if let Ok(msg) = line.parse::<IrcMessage>() {
                    black_box(msg);
                    count += 1;
                }
            }
            
            black_box(count)
        })
    });
    
    // Benchmark with many messages
    let many_messages: Vec<String> = (0..1000)
        .map(|i| format!("PRIVMSG #channel :Message {}", i))
        .collect();
    let many_messages_refs: Vec<&str> = many_messages.iter().map(|s| s.as_str()).collect();
    
    group.bench_function("many_messages", |b| {
        b.iter(|| {
            let mut conn = MockConnection::new(&many_messages_refs);
            let mut count = 0;
            
            while let Some(line) = conn.read_message() {
                if let Ok(msg) = line.parse::<IrcMessage>() {
                    black_box(msg);
                    count += 1;
                }
            }
            
            black_box(count)
        })
    });
    
    group.finish();
}

fn bench_message_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_validation");
    
    // Valid messages
    let valid_messages = vec![
        "PRIVMSG #channel :Hello world",
        "@time=2023-01-01T00:00:00.000Z PRIVMSG #channel :Hello",
        ":nick!user@host PRIVMSG #channel :Hello",
        "001 nick :Welcome to IRC",
        "353 nick = #channel :nick1 nick2 nick3",
    ];
    
    group.bench_function("valid_messages", |b| {
        b.iter(|| {
            for msg in &valid_messages {
                let result = black_box(msg.parse::<IrcMessage>());
                black_box(result);
            }
        })
    });
    
    // Invalid messages (should fail validation)
    let invalid_messages = vec![
        &"A".repeat(100), // Command too long
        "@invalid tag=value PRIVMSG #channel :test", // Invalid tag
        "PRIVMSG #channel\0 :test", // Null byte
        &format!("PRIVMSG {} :test", "a".repeat(600)), // Parameter too long
        "", // Empty message
    ];
    
    group.bench_function("invalid_messages", |b| {
        b.iter(|| {
            for msg in &invalid_messages {
                let result = black_box(msg.parse::<IrcMessage>());
                black_box(result);
            }
        })
    });
    
    group.finish();
}

fn bench_concurrent_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_simulation");
    
    // Simulate multiple connections processing messages
    let messages_per_connection = 100;
    let connections = 10;
    
    group.bench_function("multi_connection", |b| {
        b.iter(|| {
            let mut total_processed = 0;
            
            for conn_id in 0..connections {
                let messages: Vec<String> = (0..messages_per_connection)
                    .map(|i| format!("PRIVMSG #conn{} :Message {}", conn_id, i))
                    .collect();
                
                let message_refs: Vec<&str> = messages.iter().map(|s| s.as_str()).collect();
                let mut conn = MockConnection::new(&message_refs);
                
                while let Some(line) = conn.read_message() {
                    if let Ok(msg) = line.parse::<IrcMessage>() {
                        black_box(msg);
                        total_processed += 1;
                    }
                }
            }
            
            black_box(total_processed)
        })
    });
    
    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    
    // Test memory allocation patterns
    group.bench_function("message_creation", |b| {
        b.iter(|| {
            let mut messages = Vec::new();
            
            for i in 0..1000 {
                let msg = IrcMessage::new("PRIVMSG")
                    .with_params(vec![
                        format!("#channel{}", i),
                        format!("Message number {}", i)
                    ]);
                messages.push(msg);
            }
            
            black_box(messages)
        })
    });
    
    group.bench_function("message_parsing_allocation", |b| {
        let test_messages: Vec<String> = (0..1000)
            .map(|i| format!("PRIVMSG #channel{} :Message {}", i, i))
            .collect();
        
        b.iter(|| {
            let mut parsed = Vec::new();
            
            for msg_str in &test_messages {
                if let Ok(msg) = msg_str.parse::<IrcMessage>() {
                    parsed.push(msg);
                }
            }
            
            black_box(parsed)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_message_reading,
    bench_message_validation, 
    bench_concurrent_simulation,
    bench_memory_usage
);
criterion_main!(benches);