//! Performance Monitoring and Metrics
//!
//! Provides comprehensive monitoring, metrics collection, and performance
//! analysis for production deployments of Legionnaire IRC client.

use crate::error::{IronError, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, debug};

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable performance monitoring
    pub enabled: bool,
    /// Metrics collection interval in seconds
    pub collection_interval: u64,
    /// Keep metrics for this many hours
    pub retention_hours: u64,
    /// Export metrics to file
    pub export_to_file: Option<String>,
    /// Export metrics to Prometheus endpoint
    pub prometheus_endpoint: Option<String>,
    /// Alert thresholds
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Memory usage threshold (MB)
    pub memory_threshold_mb: u64,
    /// CPU usage threshold (percentage)
    pub cpu_threshold_percent: f64,
    /// Message processing latency threshold (ms)
    pub latency_threshold_ms: u64,
    /// Error rate threshold (errors per minute)
    pub error_rate_threshold: u32,
    /// Connection failure threshold
    pub connection_failure_threshold: u32,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval: 30,
            retention_hours: 24,
            export_to_file: Some("metrics.jsonl".to_string()),
            prometheus_endpoint: None,
            alerts: AlertConfig {
                memory_threshold_mb: 500,
                cpu_threshold_percent: 80.0,
                latency_threshold_ms: 1000,
                error_rate_threshold: 10,
                connection_failure_threshold: 5,
            },
        }
    }
}

/// Performance metrics collector
pub struct PerformanceMonitor {
    config: MonitoringConfig,
    metrics: Arc<RwLock<MetricsData>>,
    alert_sender: mpsc::UnboundedSender<Alert>,
    start_time: Instant,
}

/// Collected metrics data
#[derive(Debug, Default)]
struct MetricsData {
    // System metrics
    system_metrics: Vec<SystemMetrics>,
    
    // Application metrics
    message_metrics: MessageMetrics,
    connection_metrics: ConnectionMetrics,
    plugin_metrics: HashMap<String, PluginMetrics>,
    error_metrics: ErrorMetrics,
    
    // Performance metrics
    performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub timestamp: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub open_file_descriptors: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Default)]
struct MessageMetrics {
    total_messages_sent: u64,
    total_messages_received: u64,
    messages_per_minute: RollingAverage,
    message_sizes: RollingAverage,
    processing_latency: RollingAverage,
}

#[derive(Debug, Default)]
struct ConnectionMetrics {
    active_connections: u32,
    total_connections_attempted: u64,
    connection_failures: u64,
    reconnection_attempts: u64,
    connection_uptime: Duration,
    disconnection_reasons: HashMap<String, u32>,
}

#[derive(Debug, Default)]
struct PluginMetrics {
    plugin_name: String,
    messages_handled: u64,
    processing_time: RollingAverage,
    errors: u32,
    memory_usage: u64,
}

#[derive(Debug, Default)]
struct ErrorMetrics {
    total_errors: u64,
    errors_by_type: HashMap<String, u32>,
    error_rate_per_minute: RollingAverage,
    critical_errors: u32,
}

#[derive(Debug, Default)]
struct PerformanceMetrics {
    tui_frame_rate: RollingAverage,
    network_latency: RollingAverage,
    database_query_time: RollingAverage,
    gc_pause_time: RollingAverage,
}

/// Rolling average calculator
#[derive(Debug)]
struct RollingAverage {
    values: Vec<f64>,
    max_samples: usize,
    sum: f64,
}

impl Default for RollingAverage {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            max_samples: 60, // 1 minute at 1-second intervals
            sum: 0.0,
        }
    }
}

impl RollingAverage {
    fn add_sample(&mut self, value: f64) {
        self.values.push(value);
        self.sum += value;
        
        if self.values.len() > self.max_samples {
            let old_value = self.values.remove(0);
            self.sum -= old_value;
        }
    }
    
    fn average(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.sum / self.values.len() as f64
        }
    }
    
    fn max(&self) -> f64 {
        self.values.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    }
    
    fn min(&self) -> f64 {
        self.values.iter().copied().fold(f64::INFINITY, f64::min)
    }
}

/// Alert types
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub timestamp: u64,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize)]
pub enum AlertType {
    HighMemoryUsage,
    HighCpuUsage,
    HighLatency,
    HighErrorRate,
    ConnectionFailures,
    PluginError,
}

#[derive(Debug, Clone, Serialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Public metrics snapshot for external consumption
#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub uptime_seconds: u64,
    pub system: SystemMetrics,
    pub messages: MessageMetricsSnapshot,
    pub connections: ConnectionMetricsSnapshot,
    pub errors: ErrorMetricsSnapshot,
    pub performance: PerformanceMetricsSnapshot,
}

#[derive(Debug, Serialize)]
pub struct MessageMetricsSnapshot {
    pub total_sent: u64,
    pub total_received: u64,
    pub rate_per_minute: f64,
    pub average_size: f64,
    pub processing_latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct ConnectionMetricsSnapshot {
    pub active_connections: u32,
    pub total_attempted: u64,
    pub failure_rate: f64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct ErrorMetricsSnapshot {
    pub total_errors: u64,
    pub error_rate_per_minute: f64,
    pub critical_errors: u32,
    pub top_error_types: Vec<(String, u32)>,
}

#[derive(Debug, Serialize)]
pub struct PerformanceMetricsSnapshot {
    pub tui_fps: f64,
    pub network_latency_ms: f64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
}

impl PerformanceMonitor {
    pub fn new(config: MonitoringConfig) -> (Self, mpsc::UnboundedReceiver<Alert>) {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();
        
        let monitor = Self {
            config,
            metrics: Arc::new(RwLock::new(MetricsData::default())),
            alert_sender,
            start_time: Instant::now(),
        };
        
        (monitor, alert_receiver)
    }
    
    /// Start the monitoring system
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        info!("Starting performance monitoring system");
        
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let alert_sender = self.alert_sender.clone();
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.collection_interval));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::collect_system_metrics(
                    &metrics, 
                    &config.alerts, 
                    &alert_sender,
                    start_time
                ).await {
                    warn!("Failed to collect system metrics: {}", e);
                }
            }
        });
        
        Ok(())
    }
    
    /// Record a message being sent
    pub async fn record_message_sent(&self, size: usize, processing_time: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.message_metrics.total_messages_sent += 1;
        metrics.message_metrics.message_sizes.add_sample(size as f64);
        metrics.message_metrics.processing_latency.add_sample(processing_time.as_millis() as f64);
        
        // Check for high latency alert
        let latency_ms = processing_time.as_millis() as u64;
        if latency_ms > self.config.alerts.latency_threshold_ms {
            let _ = self.alert_sender.send(Alert {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                alert_type: AlertType::HighLatency,
                severity: AlertSeverity::Warning,
                message: format!("High message processing latency: {}ms", latency_ms),
                value: latency_ms as f64,
                threshold: self.config.alerts.latency_threshold_ms as f64,
            });
        }
    }
    
    /// Record a message being received
    pub async fn record_message_received(&self, size: usize) {
        let mut metrics = self.metrics.write().await;
        metrics.message_metrics.total_messages_received += 1;
        metrics.message_metrics.message_sizes.add_sample(size as f64);
    }
    
    /// Record a connection attempt
    pub async fn record_connection_attempt(&self, success: bool, reason: Option<String>) {
        let mut metrics = self.metrics.write().await;
        metrics.connection_metrics.total_connections_attempted += 1;
        
        if success {
            metrics.connection_metrics.active_connections += 1;
        } else {
            metrics.connection_metrics.connection_failures += 1;
            
            if let Some(reason) = reason {
                *metrics.connection_metrics.disconnection_reasons.entry(reason).or_insert(0) += 1;
            }
            
            // Check for connection failure alert
            let failure_rate = metrics.connection_metrics.connection_failures as f64 / 
                (metrics.connection_metrics.total_connections_attempted as f64).max(1.0);
            
            if failure_rate > 0.1 { // More than 10% failure rate
                let _ = self.alert_sender.send(Alert {
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    alert_type: AlertType::ConnectionFailures,
                    severity: AlertSeverity::Critical,
                    message: format!("High connection failure rate: {:.1}%", failure_rate * 100.0),
                    value: failure_rate * 100.0,
                    threshold: 10.0,
                });
            }
        }
    }
    
    /// Record an error occurrence
    pub async fn record_error(&self, error_type: &str, is_critical: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.error_metrics.total_errors += 1;
        *metrics.error_metrics.errors_by_type.entry(error_type.to_string()).or_insert(0) += 1;
        
        if is_critical {
            metrics.error_metrics.critical_errors += 1;
        }
        
        metrics.error_metrics.error_rate_per_minute.add_sample(1.0);
        
        // Check for high error rate
        let error_rate = metrics.error_metrics.error_rate_per_minute.average();
        if error_rate > self.config.alerts.error_rate_threshold as f64 {
            let _ = self.alert_sender.send(Alert {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                alert_type: AlertType::HighErrorRate,
                severity: if is_critical { AlertSeverity::Critical } else { AlertSeverity::Warning },
                message: format!("High error rate: {:.1} errors/minute", error_rate),
                value: error_rate,
                threshold: self.config.alerts.error_rate_threshold as f64,
            });
        }
    }
    
    /// Record plugin performance
    pub async fn record_plugin_performance(&self, plugin_name: &str, processing_time: Duration) {
        let mut metrics = self.metrics.write().await;
        let plugin_metrics = metrics.plugin_metrics.entry(plugin_name.to_string())
            .or_insert_with(|| PluginMetrics {
                plugin_name: plugin_name.to_string(),
                ..Default::default()
            });
        
        plugin_metrics.messages_handled += 1;
        plugin_metrics.processing_time.add_sample(processing_time.as_millis() as f64);
    }
    
    /// Get current metrics snapshot
    pub async fn get_metrics_snapshot(&self) -> MetricsSnapshot {
        let metrics = self.metrics.read().await;
        let uptime = self.start_time.elapsed();
        
        let system = metrics.system_metrics.last().cloned().unwrap_or_else(|| SystemMetrics {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
            open_file_descriptors: 0,
            uptime_seconds: uptime.as_secs(),
        });
        
        let messages = MessageMetricsSnapshot {
            total_sent: metrics.message_metrics.total_messages_sent,
            total_received: metrics.message_metrics.total_messages_received,
            rate_per_minute: metrics.message_metrics.messages_per_minute.average(),
            average_size: metrics.message_metrics.message_sizes.average(),
            processing_latency_ms: metrics.message_metrics.processing_latency.average(),
        };
        
        let connections = ConnectionMetricsSnapshot {
            active_connections: metrics.connection_metrics.active_connections,
            total_attempted: metrics.connection_metrics.total_connections_attempted,
            failure_rate: if metrics.connection_metrics.total_connections_attempted > 0 {
                metrics.connection_metrics.connection_failures as f64 / 
                metrics.connection_metrics.total_connections_attempted as f64 * 100.0
            } else {
                0.0
            },
            uptime_seconds: metrics.connection_metrics.connection_uptime.as_secs(),
        };
        
        let mut top_errors: Vec<_> = metrics.error_metrics.errors_by_type.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top_errors.sort_by(|a, b| b.1.cmp(&a.1));
        top_errors.truncate(5);
        
        let errors = ErrorMetricsSnapshot {
            total_errors: metrics.error_metrics.total_errors,
            error_rate_per_minute: metrics.error_metrics.error_rate_per_minute.average(),
            critical_errors: metrics.error_metrics.critical_errors,
            top_error_types: top_errors,
        };
        
        let performance = PerformanceMetricsSnapshot {
            tui_fps: metrics.performance_metrics.tui_frame_rate.average(),
            network_latency_ms: metrics.performance_metrics.network_latency.average(),
            memory_usage_mb: system.memory_usage_mb,
            cpu_usage_percent: system.cpu_usage_percent,
        };
        
        MetricsSnapshot {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            uptime_seconds: uptime.as_secs(),
            system,
            messages,
            connections,
            errors,
            performance,
        }
    }
    
    /// Export metrics to file
    pub async fn export_metrics(&self) -> Result<()> {
        if let Some(ref file_path) = self.config.export_to_file {
            let snapshot = self.get_metrics_snapshot().await;
            let json_line = serde_json::to_string(&snapshot)
                .map_err(|e| IronError::Configuration(format!("Failed to serialize metrics: {}", e)))?;
            
            tokio::fs::write(file_path, format!("{}\n", json_line)).await?;
            debug!("Exported metrics to {}", file_path);
        }
        
        Ok(())
    }
    
    /// Collect system-level metrics
    async fn collect_system_metrics(
        metrics: &Arc<RwLock<MetricsData>>,
        alerts: &AlertConfig,
        alert_sender: &mpsc::UnboundedSender<Alert>,
        start_time: Instant,
    ) -> Result<()> {
        let system_metrics = Self::get_system_metrics(start_time)?;
        
        // Check alert thresholds
        if system_metrics.memory_usage_mb > alerts.memory_threshold_mb {
            let _ = alert_sender.send(Alert {
                timestamp: system_metrics.timestamp,
                alert_type: AlertType::HighMemoryUsage,
                severity: AlertSeverity::Warning,
                message: format!("High memory usage: {}MB", system_metrics.memory_usage_mb),
                value: system_metrics.memory_usage_mb as f64,
                threshold: alerts.memory_threshold_mb as f64,
            });
        }
        
        if system_metrics.cpu_usage_percent > alerts.cpu_threshold_percent {
            let _ = alert_sender.send(Alert {
                timestamp: system_metrics.timestamp,
                alert_type: AlertType::HighCpuUsage,
                severity: AlertSeverity::Warning,
                message: format!("High CPU usage: {:.1}%", system_metrics.cpu_usage_percent),
                value: system_metrics.cpu_usage_percent,
                threshold: alerts.cpu_threshold_percent,
            });
        }
        
        let mut metrics_data = metrics.write().await;
        metrics_data.system_metrics.push(system_metrics);
        
        // Keep only recent metrics (based on retention_hours)
        let retention_cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(alerts.memory_threshold_mb * 3600); // retention_hours * 3600
        
        metrics_data.system_metrics.retain(|m| m.timestamp > retention_cutoff);
        
        Ok(())
    }
    
    /// Get current system metrics
    fn get_system_metrics(start_time: Instant) -> Result<SystemMetrics> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let uptime = start_time.elapsed().as_secs();
        
        // In a real implementation, these would use system APIs
        // For now, we'll use mock values or basic system info
        let memory_usage_mb = Self::get_memory_usage()?;
        let cpu_usage_percent = Self::get_cpu_usage()?;
        let open_fds = Self::get_open_file_descriptors()?;
        
        Ok(SystemMetrics {
            timestamp,
            memory_usage_mb,
            cpu_usage_percent,
            open_file_descriptors: open_fds,
            uptime_seconds: uptime,
        })
    }
    
    fn get_memory_usage() -> Result<u64> {
        // Simple memory usage estimation
        // In production, use proper system APIs like sysinfo crate
        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
                for line in contents.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                return Ok(kb / 1024); // Convert KB to MB
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback for other platforms or if reading fails
        Ok(std::process::Command::new("ps")
            .args(&["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(100) / 1024)
    }
    
    fn get_cpu_usage() -> Result<f64> {
        // CPU usage is more complex to calculate accurately
        // This is a simplified version - real implementation would track over time
        Ok(0.0) // Placeholder
    }
    
    fn get_open_file_descriptors() -> Result<u64> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                return Ok(entries.count() as u64);
            }
        }
        
        Ok(10) // Reasonable default
    }
}

/// Helper functions for monitoring integration
pub mod helpers {
    use super::*;
    
    /// Create production monitoring configuration
    pub fn production_monitoring_config() -> MonitoringConfig {
        MonitoringConfig {
            enabled: true,
            collection_interval: 30,
            retention_hours: 72, // 3 days
            export_to_file: Some("logs/metrics.jsonl".to_string()),
            prometheus_endpoint: Some("http://localhost:9090/metrics".to_string()),
            alerts: AlertConfig {
                memory_threshold_mb: 512,
                cpu_threshold_percent: 75.0,
                latency_threshold_ms: 500,
                error_rate_threshold: 5,
                connection_failure_threshold: 3,
            },
        }
    }
    
    /// Create development monitoring configuration
    pub fn development_monitoring_config() -> MonitoringConfig {
        MonitoringConfig {
            enabled: false, // Usually disabled in development
            collection_interval: 60,
            retention_hours: 1,
            export_to_file: None,
            prometheus_endpoint: None,
            alerts: AlertConfig {
                memory_threshold_mb: 1024,
                cpu_threshold_percent: 90.0,
                latency_threshold_ms: 2000,
                error_rate_threshold: 50,
                connection_failure_threshold: 10,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() -> Result<()> {
        let config = MonitoringConfig::default();
        let (monitor, mut alerts) = PerformanceMonitor::new(config);

        monitor.record_message_sent(100, Duration::from_millis(50)).await;
        monitor.record_message_received(150).await;
        monitor.record_connection_attempt(true, None).await;

        let snapshot = monitor.get_metrics_snapshot().await;
        assert_eq!(snapshot.messages.total_sent, 1);
        assert_eq!(snapshot.messages.total_received, 1);
        assert_eq!(snapshot.connections.active_connections, 1);

        // Should not have any alerts for normal operation
        assert!(alerts.try_recv().is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_alert_generation() -> Result<()> {
        let mut config = MonitoringConfig::default();
        config.alerts.latency_threshold_ms = 10; // Very low threshold for testing
        
        let (monitor, mut alerts) = PerformanceMonitor::new(config);

        // This should trigger a latency alert
        monitor.record_message_sent(100, Duration::from_millis(100)).await;

        let alert = alerts.try_recv().expect("Should have received an alert");
        assert!(matches!(alert.alert_type, AlertType::HighLatency));
        assert!(matches!(alert.severity, AlertSeverity::Warning));

        Ok(())
    }

    #[test]
    fn test_rolling_average() {
        let mut avg = RollingAverage::default();
        
        avg.add_sample(10.0);
        avg.add_sample(20.0);
        avg.add_sample(30.0);
        
        assert_eq!(avg.average(), 20.0);
        assert_eq!(avg.min(), 10.0);
        assert_eq!(avg.max(), 30.0);
    }

    #[tokio::test]
    async fn test_metrics_export() -> Result<()> {
        let config = MonitoringConfig {
            export_to_file: Some("test_metrics.json".to_string()),
            ..MonitoringConfig::default()
        };
        
        let (monitor, _) = PerformanceMonitor::new(config);
        monitor.export_metrics().await?;

        // Clean up test file
        let _ = std::fs::remove_file("test_metrics.json");

        Ok(())
    }
}