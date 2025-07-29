use crate::error::{IronError, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use crate::{iron_debug, iron_warn, iron_error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosProtectionConfig {
    pub message_rate_limit: u32,
    pub rate_limit_window: u64,
    pub max_messages_per_window: u32,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub read_timeout: u64,
    pub max_queue_size: usize,
    pub max_memory_per_connection: usize,
    pub total_memory_limit: usize,
    pub max_message_length: usize,
    pub max_parse_time_ms: u64,
    pub connection_cooldown: u64,
    pub violation_threshold: u32,
    pub bandwidth_limit_bytes_per_sec: u64,
    pub max_bandwidth_per_connection: u64,
    pub max_total_memory: usize,
    pub cpu_threshold: f32,
    pub enable_cpu_monitoring: bool,
}

impl Default for DosProtectionConfig {
    fn default() -> Self {
        Self {
            message_rate_limit: 100,                   // 100 msg/sec for busy servers
            rate_limit_window: 60,
            max_messages_per_window: 6000,             // 100 msg/sec * 60 sec window
            max_connections: 500,                      // Higher connection limit for busy servers
            connection_timeout: 30,
            read_timeout: 300,
            max_queue_size: 5000,                      // Larger queue for high-volume servers
            max_memory_per_connection: 5 * 1024 * 1024, // 5MB per connection
            total_memory_limit: 500 * 1024 * 1024,    // 500MB total
            max_message_length: 8704,                  // IRC max with tags (512 + 8191 + buffer)
            max_parse_time_ms: 1000,
            connection_cooldown: 60,                   // Shorter cooldown for legitimate reconnects
            violation_threshold: 10,                   // More lenient threshold
            bandwidth_limit_bytes_per_sec: 10 * 1024 * 1024, // 10MB/s
            max_bandwidth_per_connection: 1024 * 1024, // 1MB/s per connection (unchanged)
            max_total_memory: 500 * 1024 * 1024,      // 500MB total
            cpu_threshold: 90.0,                       // Higher CPU threshold
            enable_cpu_monitoring: true,
        }
    }
}

impl DosProtectionConfig {
    /// Configuration for high-volume IRC servers (e.g., Libera Chat, Freenode)
    pub fn high_volume_server() -> Self {
        Self {
            message_rate_limit: 100,                   // 100 msg/sec
            max_messages_per_window: 6000,             // 100 msg/sec * 60 sec
            max_connections: 1000,                     // Higher connection limit
            max_queue_size: 10000,                     // Large queue for busy channels
            max_memory_per_connection: 10 * 1024 * 1024, // 10MB per connection
            total_memory_limit: 1024 * 1024 * 1024,   // 1GB total
            bandwidth_limit_bytes_per_sec: 50 * 1024 * 1024, // 50MB/s
            violation_threshold: 15,                   // More lenient
            connection_cooldown: 30,                   // Shorter cooldown
            ..Default::default()
        }
    }

    /// Configuration for small/private IRC servers
    pub fn small_server() -> Self {
        Self {
            message_rate_limit: 10,                    // 10 msg/sec
            max_messages_per_window: 600,              // 10 msg/sec * 60 sec
            max_connections: 50,                       // Lower connection limit
            max_queue_size: 500,                       // Smaller queue
            max_memory_per_connection: 1024 * 1024,    // 1MB per connection
            total_memory_limit: 50 * 1024 * 1024,     // 50MB total
            bandwidth_limit_bytes_per_sec: 1024 * 1024, // 1MB/s
            violation_threshold: 3,                    // Stricter
            connection_cooldown: 300,                  // Longer cooldown
            ..Default::default()
        }
    }

    /// Configuration for development/testing (very permissive)
    pub fn development() -> Self {
        Self {
            message_rate_limit: 1000,                  // Very high for testing
            max_messages_per_window: 60000,            // Very high window
            max_connections: 10,                       // Low connections for dev
            max_queue_size: 1000,                      
            max_memory_per_connection: 1024 * 1024,    // 1MB per connection
            total_memory_limit: 100 * 1024 * 1024,    // 100MB total
            bandwidth_limit_bytes_per_sec: 100 * 1024 * 1024, // 100MB/s
            violation_threshold: 50,                   // Very lenient
            connection_cooldown: 5,                    // Very short cooldown
            cpu_threshold: 95.0,                       // High CPU threshold
            ..Default::default()
        }
    }
}


/// Rate limiter using a sliding window approach
#[derive(Debug)]
pub struct RateLimiter {
    messages: VecDeque<Instant>,
    max_messages: u32,
    window_duration: Duration,
    last_cleanup: Instant,
}

impl RateLimiter {
    pub fn new(max_messages: u32, window_duration: Duration) -> Self {
        Self {
            messages: VecDeque::new(),
            max_messages,
            window_duration,
            last_cleanup: Instant::now(),
        }
    }

    pub fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        
        // Clean up old messages every 5 seconds to prevent memory growth
        if now.duration_since(self.last_cleanup) > Duration::from_secs(5) {
            self.cleanup_old_messages(now);
            self.last_cleanup = now;
        }

        // Remove messages outside the window
        while let Some(&front) = self.messages.front() {
            if now.duration_since(front) > self.window_duration {
                self.messages.pop_front();
            } else {
                break;
            }
        }

        // Check if we're within the limit
        if self.messages.len() >= self.max_messages as usize {
            false
        } else {
            self.messages.push_back(now);
            true
        }
    }

    fn cleanup_old_messages(&mut self, now: Instant) {
        self.messages.retain(|&msg_time| {
            now.duration_since(msg_time) <= self.window_duration
        });
    }

    pub fn messages_in_window(&self) -> usize {
        self.messages.len()
    }
}

/// Bandwidth monitor for connection throttling
#[derive(Debug)]
pub struct BandwidthMonitor {
    bytes_transferred: VecDeque<(Instant, usize)>,
    max_bytes_per_second: u64,
    window_duration: Duration,
}

impl BandwidthMonitor {
    pub fn new(max_bytes_per_second: u64) -> Self {
        Self {
            bytes_transferred: VecDeque::new(),
            max_bytes_per_second,
            window_duration: Duration::from_secs(1),
        }
    }

    pub fn record_transfer(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        
        // Clean up old entries
        while let Some(&(time, _)) = self.bytes_transferred.front() {
            if now.duration_since(time) > self.window_duration {
                self.bytes_transferred.pop_front();
            } else {
                break;
            }
        }

        // Calculate current usage
        let current_bytes: usize = self.bytes_transferred
            .iter()
            .map(|(_, bytes)| *bytes)
            .sum();

        if current_bytes + bytes > self.max_bytes_per_second as usize {
            false // Would exceed bandwidth limit
        } else {
            self.bytes_transferred.push_back((now, bytes));
            true
        }
    }

    pub fn current_usage(&self) -> u64 {
        let now = Instant::now();
        self.bytes_transferred
            .iter()
            .filter(|(time, _)| now.duration_since(*time) <= self.window_duration)
            .map(|(_, bytes)| *bytes as u64)
            .sum()
    }
}

/// Memory usage tracker
#[derive(Debug)]
pub struct MemoryTracker {
    usage: usize,
    max_usage: usize,
}

impl MemoryTracker {
    pub fn new(max_usage: usize) -> Self {
        Self {
            usage: 0,
            max_usage,
        }
    }

    pub fn allocate(&mut self, size: usize) -> bool {
        if self.usage + size > self.max_usage {
            false
        } else {
            self.usage += size;
            true
        }
    }

    pub fn deallocate(&mut self, size: usize) {
        self.usage = self.usage.saturating_sub(size);
    }

    pub fn current_usage(&self) -> usize {
        self.usage
    }

    pub fn usage_percentage(&self) -> f32 {
        (self.usage as f32 / self.max_usage as f32) * 100.0
    }
}

/// Connection-specific DoS protection state
#[derive(Debug)]
pub struct ConnectionState {
    pub rate_limiter: RateLimiter,
    pub bandwidth_monitor: BandwidthMonitor,
    pub memory_tracker: MemoryTracker,
    pub connection_start: Instant,
    pub last_activity: Instant,
    pub message_queue_size: usize,
    pub total_messages: u64,
    pub total_bytes: u64,
    pub violation_count: u32,
    pub is_blocked: bool,
    pub block_until: Option<Instant>,
}

impl ConnectionState {
    pub fn new(config: &DosProtectionConfig) -> Self {
        let now = Instant::now();
        Self {
            rate_limiter: RateLimiter::new(
                config.max_messages_per_window,
                Duration::from_secs(config.rate_limit_window),
            ),
            bandwidth_monitor: BandwidthMonitor::new(config.max_bandwidth_per_connection),
            memory_tracker: MemoryTracker::new(config.max_memory_per_connection),
            connection_start: now,
            last_activity: now,
            message_queue_size: 0,
            total_messages: 0,
            total_bytes: 0,
            violation_count: 0,
            is_blocked: false,
            block_until: None,
        }
    }

    pub fn is_connection_blocked(&self) -> bool {
        if let Some(block_until) = self.block_until {
            if Instant::now() < block_until {
                return true;
            }
        }
        self.is_blocked
    }

    pub fn block_connection(&mut self, duration: Duration) {
        self.is_blocked = true;
        self.block_until = Some(Instant::now() + duration);
        iron_warn!("dos_protection", "Connection blocked for {} seconds due to violations", duration.as_secs());
    }

    pub fn record_violation(&mut self) {
        self.violation_count += 1;
        
        // Progressive blocking based on violation count
        let block_duration = match self.violation_count {
            1..=3 => Duration::from_secs(60),
            4..=10 => Duration::from_secs(300),
            _ => Duration::from_secs(900),
        };
        
        self.block_connection(block_duration);
    }
}

/// CPU usage monitor
#[derive(Debug)]
pub struct CpuMonitor {
    last_check: Instant,
    samples: VecDeque<f32>,
    threshold: f32,
    enabled: bool,
}

impl CpuMonitor {
    pub fn new(threshold: f32, enabled: bool) -> Self {
        Self {
            last_check: Instant::now(),
            samples: VecDeque::new(),
            threshold,
            enabled,
        }
    }

    pub fn check_cpu_usage(&mut self) -> bool {
        if !self.enabled {
            return true;
        }

        let now = Instant::now();
        if now.duration_since(self.last_check) < Duration::from_secs(1) {
            return true; // Don't check too frequently
        }

        // Simulate CPU monitoring (in a real implementation, you'd use system metrics)
        let current_usage = self.get_current_cpu_usage();
        self.samples.push_back(current_usage);
        
        // Keep only last 10 samples
        if self.samples.len() > 10 {
            self.samples.pop_front();
        }

        let avg_usage: f32 = self.samples.iter().sum::<f32>() / self.samples.len() as f32;
        self.last_check = now;

        avg_usage < self.threshold
    }

    fn get_current_cpu_usage(&self) -> f32 {
        // Placeholder implementation - in a real system, this would read from /proc/stat
        // or use a system monitoring library
        50.0 // Return a safe default
    }
}

/// Main DoS protection coordinator
pub struct DosProtection {
    config: DosProtectionConfig,
    connections: Arc<Mutex<HashMap<String, ConnectionState>>>,
    global_memory: Arc<Mutex<MemoryTracker>>,
    connection_semaphore: Arc<Semaphore>,
    cpu_monitor: Arc<Mutex<CpuMonitor>>,
    blocked_ips: Arc<Mutex<HashMap<String, Instant>>>,
}

impl DosProtection {
    pub fn new(config: DosProtectionConfig) -> Self {
        let global_memory = MemoryTracker::new(config.max_total_memory);
        let cpu_monitor = CpuMonitor::new(config.cpu_threshold, config.enable_cpu_monitoring);
        
        Self {
            connection_semaphore: Arc::new(Semaphore::new(config.max_connections as usize)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            global_memory: Arc::new(Mutex::new(global_memory)),
            cpu_monitor: Arc::new(Mutex::new(cpu_monitor)),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Register a new connection
    pub async fn register_connection(&self, connection_id: String) -> Result<()> {
        // Check if we have connection capacity
        let _permit = self.connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IronError::Connection("Too many connections".to_string()))?;

        // Check if IP is blocked
        let ip = self.extract_ip(&connection_id);
        {
            let blocked_ips = self.blocked_ips.lock().await;
            if let Some(&block_time) = blocked_ips.get(&ip) {
                if Instant::now().duration_since(block_time) < Duration::from_secs(self.config.connection_cooldown) {
                    return Err(IronError::SecurityViolation("IP temporarily blocked".to_string()));
                }
            }
        }

        let mut connections = self.connections.lock().await;
        connections.insert(connection_id.clone(), ConnectionState::new(&self.config));
        
        iron_debug!("dos_protection", "Registered connection: {}", connection_id);
        Ok(())
    }

    /// Unregister a connection and cleanup resources
    pub async fn unregister_connection(&self, connection_id: &str) {
        let mut connections = self.connections.lock().await;
        if let Some(state) = connections.remove(connection_id) {
            // Cleanup memory usage
            let mut global_memory = self.global_memory.lock().await;
            global_memory.deallocate(state.memory_tracker.current_usage());
            
            iron_debug!("dos_protection", "Unregistered connection: {}", connection_id);
        }
    }

    /// Check if a message should be allowed
    pub async fn check_message(&self, connection_id: &str, message: &str) -> Result<()> {
        let mut connections = self.connections.lock().await;
        let state = connections.get_mut(connection_id)
            .ok_or_else(|| IronError::Connection("Connection not registered".to_string()))?;

        // Check if connection is blocked
        if state.is_connection_blocked() {
            return Err(IronError::SecurityViolation("Connection temporarily blocked".to_string()));
        }

        // Check message length
        if message.len() > self.config.max_message_length {
            state.record_violation();
            return Err(IronError::SecurityViolation("Message too long".to_string()));
        }

        // Check rate limit
        if !state.rate_limiter.check_rate_limit() {
            state.record_violation();
            iron_warn!("dos_protection", "Rate limit exceeded for connection: {}", connection_id);
            return Err(IronError::SecurityViolation("Rate limit exceeded".to_string()));
        }

        // Check bandwidth
        if !state.bandwidth_monitor.record_transfer(message.len()) {
            state.record_violation();
            return Err(IronError::SecurityViolation("Bandwidth limit exceeded".to_string()));
        }

        // Check memory allocation
        let mut global_memory = self.global_memory.lock().await;
        if !global_memory.allocate(message.len()) || !state.memory_tracker.allocate(message.len()) {
            global_memory.deallocate(message.len()); // Rollback global allocation
            state.record_violation();
            return Err(IronError::SecurityViolation("Memory limit exceeded".to_string()));
        }

        // Check CPU usage
        let mut cpu_monitor = self.cpu_monitor.lock().await;
        if !cpu_monitor.check_cpu_usage() {
            // Don't record as violation for CPU, just throttle
            return Err(IronError::SecurityViolation("System under high load".to_string()));
        }

        // Update statistics
        state.total_messages += 1;
        state.total_bytes += message.len() as u64;
        state.last_activity = Instant::now();

        Ok(())
    }

    /// Check parsing timeout
    pub async fn check_parse_timeout(&self, start_time: Instant) -> Result<()> {
        let elapsed = start_time.elapsed();
        if elapsed > Duration::from_millis(self.config.max_parse_time_ms) {
            iron_error!("dos_protection", "Message parsing timeout: {}ms", elapsed.as_millis());
            return Err(IronError::SecurityViolation("Message parsing timeout".to_string()));
        }
        Ok(())
    }

    /// Update queue size for a connection
    pub async fn update_queue_size(&self, connection_id: &str, size: usize) -> Result<()> {
        let mut connections = self.connections.lock().await;
        let state = connections.get_mut(connection_id)
            .ok_or_else(|| IronError::Connection("Connection not registered".to_string()))?;

        if size > self.config.max_queue_size {
            state.record_violation();
            return Err(IronError::SecurityViolation("Message queue too large".to_string()));
        }

        state.message_queue_size = size;
        Ok(())
    }

    /// Get connection statistics
    pub async fn get_connection_stats(&self, connection_id: &str) -> Option<ConnectionStats> {
        let connections = self.connections.lock().await;
        connections.get(connection_id).map(|state| {
            ConnectionStats {
                messages_in_window: state.rate_limiter.messages_in_window(),
                bandwidth_usage: state.bandwidth_monitor.current_usage(),
                memory_usage: state.memory_tracker.current_usage(),
                total_messages: state.total_messages,
                total_bytes: state.total_bytes,
                violation_count: state.violation_count,
                is_blocked: state.is_connection_blocked(),
                uptime: state.connection_start.elapsed(),
            }
        })
    }

    /// Get global statistics
    pub async fn get_global_stats(&self) -> GlobalStats {
        let connections = self.connections.lock().await;
        let global_memory = self.global_memory.lock().await;
        
        GlobalStats {
            active_connections: connections.len(),
            total_memory_usage: global_memory.current_usage(),
            memory_usage_percentage: global_memory.usage_percentage(),
            available_connections: self.connection_semaphore.available_permits(),
        }
    }

    /// Cleanup expired blocks and old connection data
    pub async fn cleanup_expired(&self) {
        let mut connections = self.connections.lock().await;
        let mut blocked_ips = self.blocked_ips.lock().await;
        let now = Instant::now();

        // Remove expired IP blocks
        blocked_ips.retain(|_, &mut block_time| {
            now.duration_since(block_time) < Duration::from_secs(self.config.connection_cooldown)
        });

        // Remove old connection states that haven't been active
        connections.retain(|_, state| {
            now.duration_since(state.last_activity) < Duration::from_secs(self.config.connection_cooldown)
        });
    }

    fn extract_ip(&self, connection_id: &str) -> String {
        // Extract IP from connection ID (assuming format like "ip:port")
        connection_id.split(':').next().unwrap_or(connection_id).to_string()
    }

    /// Block an IP address
    pub async fn block_ip(&self, ip: String) {
        let mut blocked_ips = self.blocked_ips.lock().await;
        blocked_ips.insert(ip, Instant::now());
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub messages_in_window: usize,
    pub bandwidth_usage: u64,
    pub memory_usage: usize,
    pub total_messages: u64,
    pub total_bytes: u64,
    pub violation_count: u32,
    pub is_blocked: bool,
    pub uptime: Duration,
}

#[derive(Debug, Clone)]
pub struct GlobalStats {
    pub active_connections: usize,
    pub total_memory_usage: usize,
    pub memory_usage_percentage: f32,
    pub available_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = DosProtectionConfig::default();
        let dos = DosProtection::new(config);
        
        dos.register_connection("test:123".to_string()).await.unwrap();
        
        // Should allow first few messages
        for i in 0..5 {
            assert!(dos.check_message("test:123", &format!("message {}", i)).await.is_ok());
        }
        
        // Should block after rate limit
        assert!(dos.check_message("test:123", "too many messages").await.is_err());
    }

    #[test]
    fn test_bandwidth_monitor() {
        let mut monitor = BandwidthMonitor::new(100); // 100 bytes per second
        
        // Should allow small transfers
        assert!(monitor.record_transfer(50));
        assert!(monitor.record_transfer(49));
        
        // Should block transfer that exceeds limit
        assert!(!monitor.record_transfer(2));
    }

    #[test]
    fn test_memory_tracker() {
        let mut tracker = MemoryTracker::new(1000);
        
        assert!(tracker.allocate(500));
        assert!(tracker.allocate(400));
        assert!(!tracker.allocate(200)); // Would exceed limit
        
        tracker.deallocate(300);
        assert!(tracker.allocate(200)); // Should work now
    }
}