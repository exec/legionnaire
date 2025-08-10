//! Performance Benchmark Tests
//!
//! Comprehensive performance tests and benchmarks to ensure
//! Legionnaire can handle production workloads efficiently.

use legionnaire::{
    IronClient, IrcConfig, PerformanceMonitor, MonitoringConfig,
    SecurityValidator, SecurityConfig
};
use legion_protocol::IrcMessage;
use anyhow::Result;
use serial_test::serial;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/// Benchmark message parsing performance
#[tokio::test]
#[serial]
async fn benchmark_message_parsing() -> Result<()> {
    println!("🚀 Benchmarking message parsing performance...");

    let test_messages = vec![
        ":nick!user@host PRIVMSG #channel :Hello world!",
        ":server.example.com 001 nick :Welcome to the IRC network",
        ":nick!user@host JOIN #channel",
        ":nick!user@host PART #channel :Goodbye",
        ":server.example.com 353 nick @ #channel :nick1 nick2 nick3",
        ":nick!user@host QUIT :Client Quit",
        "PING :server.example.com",
        ":server.example.com PONG server.example.com :client",
        ":nick!user@host MODE #channel +o othernick",
        ":nick!user@host KICK #channel badnick :You're out!",
    ];

    let iterations = 10000;
    let start_time = Instant::now();

    for _ in 0..iterations {
        for raw_message in &test_messages {
            let message = IrcMessage::parse(raw_message);
            // Verify parsing worked
            assert!(message.is_ok(), "Failed to parse: {}", raw_message);
        }
    }

    let duration = start_time.elapsed();
    let total_messages = iterations * test_messages.len();
    let throughput = total_messages as f64 / duration.as_secs_f64();

    println!("📊 Message parsing benchmark results:");
    println!("  - Total messages: {}", total_messages);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} messages/sec", throughput);
    println!("  - Average time per message: {:.2}µs", 
             duration.as_micros() as f64 / total_messages as f64);

    // Should parse at least 50,000 messages per second
    assert!(throughput > 50000.0, "Message parsing too slow: {:.0} msg/sec", throughput);

    println!("✅ Message parsing performance acceptable");
    Ok(())
}

/// Benchmark message serialization performance
#[tokio::test]
#[serial]
async fn benchmark_message_serialization() -> Result<()> {
    println!("🚀 Benchmarking message serialization performance...");

    let test_messages = vec![
        IrcMessage::new("PRIVMSG")
            .with_prefix("nick!user@host".to_string())
            .with_params(vec!["#channel".to_string(), "Hello world!".to_string()]),
        IrcMessage::new("JOIN")
            .with_prefix("nick!user@host".to_string())
            .with_params(vec!["#channel".to_string()]),
        IrcMessage::new("PART")
            .with_prefix("nick!user@host".to_string())
            .with_params(vec!["#channel".to_string(), "Goodbye".to_string()]),
        IrcMessage::new("PING")
            .with_params(vec!["server.example.com".to_string()]),
        IrcMessage::new("PONG")
            .with_prefix("server.example.com".to_string())
            .with_params(vec!["server.example.com".to_string(), "client".to_string()]),
    ];

    let iterations = 10000;
    let start_time = Instant::now();

    for _ in 0..iterations {
        for message in &test_messages {
            let serialized = message.to_string();
            // Verify serialization produced output
            assert!(!serialized.is_empty(), "Serialization produced empty string");
        }
    }

    let duration = start_time.elapsed();
    let total_messages = iterations * test_messages.len();
    let throughput = total_messages as f64 / duration.as_secs_f64();

    println!("📊 Message serialization benchmark results:");
    println!("  - Total messages: {}", total_messages);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} messages/sec", throughput);

    assert!(throughput > 30000.0, "Message serialization too slow: {:.0} msg/sec", throughput);

    println!("✅ Message serialization performance acceptable");
    Ok(())
}

/// Benchmark security validation performance
#[tokio::test]
#[serial]
async fn benchmark_security_validation() -> Result<()> {
    println!("🚀 Benchmarking security validation performance...");

    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    let test_messages = vec![
        "Hello world!",
        "How are you doing today?",
        "This is a longer message with some more content to validate",
        "Unicode message: 🌍 Hello 世界!",
        "Message with numbers: 1234567890",
        "Message with symbols: !@#$%^&*()",
        "URL in message: https://example.com/path",
        "Channel mention: Check out #general",
        "Nick mention: @alice how are you?",
        "Command-like text: /me is testing",
    ];

    let iterations = 5000;
    let start_time = Instant::now();

    for i in 0..iterations {
        let client_id = format!("user_{}", i % 100); // Simulate 100 different users
        
        for message in &test_messages {
            let result = validator.validate_message(&client_id, message, None).await;
            // Most messages should pass validation
            assert!(result.is_ok(), "Validation failed for: {}", message);
        }
    }

    let duration = start_time.elapsed();
    let total_validations = iterations * test_messages.len();
    let throughput = total_validations as f64 / duration.as_secs_f64();

    println!("📊 Security validation benchmark results:");
    println!("  - Total validations: {}", total_validations);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} validations/sec", throughput);

    assert!(throughput > 10000.0, "Security validation too slow: {:.0} validations/sec", throughput);

    println!("✅ Security validation performance acceptable");
    Ok(())
}

/// Benchmark memory usage under load
#[tokio::test]
#[serial]
async fn benchmark_memory_usage() -> Result<()> {
    println!("🚀 Benchmarking memory usage under message load...");

    let initial_memory = get_memory_usage_mb();
    println!("Initial memory usage: {}MB", initial_memory);

    // Create a large number of messages in memory
    let message_count = 50000;
    let mut messages = Vec::with_capacity(message_count);

    let start_time = Instant::now();

    for i in 0..message_count {
        let message = IrcMessage::new("PRIVMSG")
            .with_prefix(format!("user{}!test@example.com", i % 1000))
            .with_params(vec![
                "#channel".to_string(),
                format!("Message number {} with some content", i)
            ]);
        messages.push(message);
    }

    let creation_time = start_time.elapsed();
    let peak_memory = get_memory_usage_mb();
    let memory_increase = peak_memory - initial_memory;

    // Process all messages
    let mut processed = 0;
    let process_start = Instant::now();

    for message in &messages {
        // Simulate processing
        let _serialized = message.to_string();
        processed += 1;
    }

    let processing_time = process_start.elapsed();

    // Clean up
    messages.clear();
    drop(messages);

    // Force garbage collection (if available)
    #[cfg(not(target_env = "msvc"))]
    {
        // Give time for memory to be reclaimed
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let final_memory = get_memory_usage_mb();

    println!("📊 Memory usage benchmark results:");
    println!("  - Messages created: {}", message_count);
    println!("  - Creation time: {:?}", creation_time);
    println!("  - Processing time: {:?}", processing_time);
    println!("  - Initial memory: {}MB", initial_memory);
    println!("  - Peak memory: {}MB", peak_memory);
    println!("  - Memory increase: {}MB", memory_increase);
    println!("  - Final memory: {}MB", final_memory);
    println!("  - Memory per message: {:.2}KB", 
             (memory_increase as f64 * 1024.0) / message_count as f64);

    // Memory usage should be reasonable
    assert!(memory_increase < 500, "Memory usage too high: {}MB", memory_increase);
    assert!(processed == message_count, "Not all messages processed");

    println!("✅ Memory usage under load acceptable");
    Ok(())
}

/// Benchmark concurrent message handling
#[tokio::test]
#[serial]
async fn benchmark_concurrent_message_handling() -> Result<()> {
    println!("🚀 Benchmarking concurrent message handling...");

    let message_count_per_task = 1000;
    let concurrent_tasks = 10;
    let total_messages = message_count_per_task * concurrent_tasks;

    let start_time = Instant::now();

    // Spawn concurrent tasks
    let tasks: Vec<_> = (0..concurrent_tasks)
        .map(|task_id| {
            tokio::spawn(async move {
                let mut processed = 0;
                
                for i in 0..message_count_per_task {
                    let message = IrcMessage::new("PRIVMSG")
                        .with_prefix(format!("user{}!test@host", task_id))
                        .with_params(vec![
                            "#channel".to_string(),
                            format!("Task {} message {}", task_id, i)
                        ]);
                    
                    // Simulate processing
                    let _serialized = message.to_string();
                    let _parsed = IrcMessage::parse(&_serialized).unwrap();
                    processed += 1;
                }
                
                processed
            })
        })
        .collect();

    // Wait for all tasks to complete
    let mut total_processed = 0;
    for task in tasks {
        total_processed += task.await.unwrap();
    }

    let duration = start_time.elapsed();
    let throughput = total_processed as f64 / duration.as_secs_f64();

    println!("📊 Concurrent message handling benchmark results:");
    println!("  - Concurrent tasks: {}", concurrent_tasks);
    println!("  - Messages per task: {}", message_count_per_task);
    println!("  - Total messages processed: {}", total_processed);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} messages/sec", throughput);

    assert_eq!(total_processed, total_messages, "Not all messages processed");
    assert!(throughput > 20000.0, "Concurrent handling too slow: {:.0} msg/sec", throughput);

    println!("✅ Concurrent message handling performance acceptable");
    Ok(())
}

/// Benchmark connection handling performance
#[tokio::test]
#[serial]
async fn benchmark_connection_handling() -> Result<()> {
    println!("🚀 Benchmarking connection handling performance...");

    let config = SecurityConfig::default();
    let validator = SecurityValidator::new(config)?;

    let connection_attempts = 1000;
    let start_time = Instant::now();

    for i in 0..connection_attempts {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i / 65536) as u8,
            ((i / 256) % 256) as u8,
            (i % 256) as u8
        ));
        
        let result = validator.validate_connection(ip).await;
        // Most connections should succeed (unless throttled)
        if result.is_err() && i < 100 {
            // Early connections should succeed
            panic!("Unexpected connection rejection at attempt {}", i);
        }
    }

    let duration = start_time.elapsed();
    let throughput = connection_attempts as f64 / duration.as_secs_f64();

    println!("📊 Connection handling benchmark results:");
    println!("  - Connection attempts: {}", connection_attempts);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} connections/sec", throughput);

    assert!(throughput > 5000.0, "Connection handling too slow: {:.0} conn/sec", throughput);

    println!("✅ Connection handling performance acceptable");
    Ok(())
}

/// Benchmark monitoring system performance
#[tokio::test]
#[serial]
async fn benchmark_monitoring_system() -> Result<()> {
    println!("🚀 Benchmarking monitoring system performance...");

    let config = MonitoringConfig::default();
    let (monitor, mut _alert_receiver) = PerformanceMonitor::new(config);

    let metrics_operations = 5000;
    let start_time = Instant::now();

    for i in 0..metrics_operations {
        // Simulate various monitoring operations
        monitor.record_message_sent(100, Duration::from_millis(1)).await;
        monitor.record_message_received(150).await;
        
        if i % 10 == 0 {
            monitor.record_connection_attempt(true, None).await;
        }
        
        if i % 100 == 0 {
            monitor.record_error("test_error", false).await;
        }
        
        if i % 50 == 0 {
            monitor.record_plugin_performance("test_plugin", Duration::from_millis(2)).await;
        }
    }

    // Get metrics snapshot (this also benchmarks snapshot generation)
    let snapshot_start = Instant::now();
    let _snapshot = monitor.get_metrics_snapshot().await;
    let snapshot_time = snapshot_start.elapsed();

    let duration = start_time.elapsed();
    let throughput = metrics_operations as f64 / duration.as_secs_f64();

    println!("📊 Monitoring system benchmark results:");
    println!("  - Metrics operations: {}", metrics_operations);
    println!("  - Duration: {:?}", duration);
    println!("  - Throughput: {:.0} operations/sec", throughput);
    println!("  - Snapshot generation time: {:?}", snapshot_time);

    assert!(throughput > 10000.0, "Monitoring too slow: {:.0} ops/sec", throughput);
    assert!(snapshot_time < Duration::from_millis(10), "Snapshot generation too slow");

    println!("✅ Monitoring system performance acceptable");
    Ok(())
}

/// Benchmark large channel simulation
#[tokio::test]
#[serial]
async fn benchmark_large_channel_simulation() -> Result<()> {
    println!("🚀 Benchmarking large channel simulation...");

    // Simulate a large active channel with many users
    let user_count = 500;
    let messages_per_user = 20;
    let total_messages = user_count * messages_per_user;

    let messages = Arc::new(RwLock::new(Vec::new()));
    let start_time = Instant::now();

    // Create concurrent tasks for users
    let tasks: Vec<_> = (0..user_count)
        .map(|user_id| {
            let messages = Arc::clone(&messages);
            tokio::spawn(async move {
                let username = format!("user_{}", user_id);
                let mut user_messages = Vec::new();
                
                for msg_id in 0..messages_per_user {
                    let message = IrcMessage::new("PRIVMSG")
                        .with_prefix(format!("{}!user@host.example.com", username))
                        .with_params(vec![
                            "#largechannel".to_string(),
                            format!("Message {} from {}", msg_id, username)
                        ]);
                    
                    user_messages.push(message);
                }
                
                // Batch insert to reduce lock contention
                let mut all_messages = messages.write().await;
                all_messages.extend(user_messages);
                
                messages_per_user
            })
        })
        .collect();

    // Wait for all tasks
    let mut total_processed = 0;
    for task in tasks {
        total_processed += task.await.unwrap();
    }

    let creation_time = start_time.elapsed();

    // Now process all messages
    let process_start = Instant::now();
    let messages_lock = messages.read().await;
    let message_count = messages_lock.len();

    for message in messages_lock.iter() {
        // Simulate message processing
        let _serialized = message.to_string();
        // Simulate some processing overhead
        if message.params.len() > 1 && !message.params[1].is_empty() {
            // Message has content
        }
    }

    drop(messages_lock); // Release the lock
    let processing_time = process_start.elapsed();
    let total_time = start_time.elapsed();

    let creation_throughput = total_processed as f64 / creation_time.as_secs_f64();
    let processing_throughput = message_count as f64 / processing_time.as_secs_f64();

    println!("📊 Large channel simulation benchmark results:");
    println!("  - Simulated users: {}", user_count);
    println!("  - Messages per user: {}", messages_per_user);
    println!("  - Total messages: {}", message_count);
    println!("  - Creation time: {:?}", creation_time);
    println!("  - Processing time: {:?}", processing_time);
    println!("  - Total time: {:?}", total_time);
    println!("  - Creation throughput: {:.0} messages/sec", creation_throughput);
    println!("  - Processing throughput: {:.0} messages/sec", processing_throughput);

    assert_eq!(message_count, total_messages, "Message count mismatch");
    assert!(creation_throughput > 5000.0, "Message creation too slow");
    assert!(processing_throughput > 50000.0, "Message processing too slow");

    println!("✅ Large channel simulation performance acceptable");
    Ok(())
}

/// Benchmark startup and initialization time
#[tokio::test]
#[serial]
async fn benchmark_startup_initialization() -> Result<()> {
    println!("🚀 Benchmarking startup and initialization time...");

    // Measure security validator initialization
    let security_start = Instant::now();
    let security_config = SecurityConfig::default();
    let _security_validator = SecurityValidator::new(security_config)?;
    let security_init_time = security_start.elapsed();

    // Measure monitoring system initialization
    let monitoring_start = Instant::now();
    let monitoring_config = MonitoringConfig::default();
    let (_monitor, _alert_receiver) = PerformanceMonitor::new(monitoring_config);
    let monitoring_init_time = monitoring_start.elapsed();

    // Measure IRC config creation
    let config_start = Instant::now();
    let _irc_config = IrcConfig {
        server: "irc.example.com".to_string(),
        port: 6667,
        nickname: "testuser".to_string(),
        username: "test".to_string(),
        realname: "Test User".to_string(),
        channels: vec!["#general".to_string(), "#random".to_string()],
        tls_required: false,
        verify_certificates: false,
        ..IrcConfig::default()
    };
    let config_init_time = config_start.elapsed();

    let total_init_time = security_init_time + monitoring_init_time + config_init_time;

    println!("📊 Startup initialization benchmark results:");
    println!("  - Security validator init: {:?}", security_init_time);
    println!("  - Monitoring system init: {:?}", monitoring_init_time);
    println!("  - IRC config creation: {:?}", config_init_time);
    println!("  - Total initialization time: {:?}", total_init_time);

    // Initialization should be fast (under 100ms total)
    assert!(total_init_time < Duration::from_millis(100), 
            "Initialization too slow: {:?}", total_init_time);

    println!("✅ Startup initialization performance acceptable");
    Ok(())
}

/// Get current memory usage in MB (simplified)
fn get_memory_usage_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
            for line in contents.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return kb / 1024; // Convert KB to MB
                        }
                    }
                }
            }
        }
    }

    // Fallback estimation
    100 // Default estimation
}

/// Stress test: Maximum sustainable throughput
#[tokio::test]
#[serial]
async fn stress_test_maximum_throughput() -> Result<()> {
    println!("🔥 Stress test: Finding maximum sustainable throughput...");

    let test_duration = Duration::from_secs(10);
    let mut message_count = 0u64;
    let start_time = Instant::now();

    // Create a high-load scenario
    let concurrent_producers = 8;
    let batch_size = 100;

    let message_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    
    let tasks: Vec<_> = (0..concurrent_producers)
        .map(|producer_id| {
            let counter = Arc::clone(&message_counter);
            tokio::spawn(async move {
                let mut local_count = 0u64;
                
                while start_time.elapsed() < test_duration {
                    // Process a batch of messages
                    for i in 0..batch_size {
                        let message = IrcMessage::new("PRIVMSG")
                            .with_prefix(format!("producer{}!test@host", producer_id))
                            .with_params(vec![
                                "#stress".to_string(),
                                format!("Stress message {} from producer {}", i, producer_id)
                            ]);
                        
                        // Simulate full message processing pipeline
                        let _serialized = message.to_string();
                        let _parsed = IrcMessage::parse(&_serialized)?;
                        
                        local_count += 1;
                    }
                    
                    counter.fetch_add(batch_size, std::sync::atomic::Ordering::Relaxed);
                    
                    // Small yield to prevent monopolizing CPU
                    tokio::task::yield_now().await;
                }
                
                Ok::<u64, anyhow::Error>(local_count)
            })
        })
        .collect();

    // Wait for all tasks or timeout
    for task in tasks {
        if let Ok(Ok(count)) = task.await {
            message_count += count;
        }
    }

    let actual_duration = start_time.elapsed();
    let throughput = message_count as f64 / actual_duration.as_secs_f64();
    let final_counter = message_counter.load(std::sync::atomic::Ordering::Relaxed);

    println!("🔥 Maximum throughput stress test results:");
    println!("  - Test duration: {:?}", actual_duration);
    println!("  - Concurrent producers: {}", concurrent_producers);
    println!("  - Total messages processed: {}", message_count);
    println!("  - Counter value: {}", final_counter);
    println!("  - Maximum sustained throughput: {:.0} messages/sec", throughput);
    println!("  - Average latency: {:.2}µs per message", 
             actual_duration.as_micros() as f64 / message_count as f64);

    // Should sustain at least 30,000 messages per second under stress
    assert!(throughput > 30000.0, "Maximum throughput too low: {:.0} msg/sec", throughput);

    println!("✅ Stress test completed - system can handle high load");
    Ok(())
}