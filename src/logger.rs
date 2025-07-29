use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::PathBuf;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
    
    pub fn color(&self) -> &str {
        match self {
            LogLevel::Debug => "\x1b[34m", // Blue
            LogLevel::Info => "\x1b[32m",  // Green
            LogLevel::Warn => "\x1b[33m",  // Yellow
            LogLevel::Error => "\x1b[31m", // Red
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub target: String,
    pub message: String,
}

impl LogEntry {
    pub fn formatted(&self) -> String {
        format!(
            "[{}] {} [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            self.level.as_str(),
            self.target,
            self.message
        )
    }
    
    pub fn formatted_colored(&self) -> String {
        format!(
            "[{}] {}{}\x1b[0m [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            self.level.color(),
            self.level.as_str(),
            self.target,
            self.message
        )
    }
}

pub struct IronLogger {
    file_writer: Arc<Mutex<BufWriter<File>>>,
    in_memory_logs: Arc<Mutex<VecDeque<LogEntry>>>,
    max_memory_logs: usize,
}

impl IronLogger {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create log file in home directory
        let mut log_path = PathBuf::from(std::env::var("HOME")?);
        log_path.push(".ironchat.log");
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        
        let file_writer = Arc::new(Mutex::new(BufWriter::new(file)));
        let in_memory_logs = Arc::new(Mutex::new(VecDeque::new()));
        
        Ok(Self {
            file_writer,
            in_memory_logs,
            max_memory_logs: 1000, // Keep last 1000 log entries in memory
        })
    }
    
    pub fn log(&self, level: LogLevel, target: &str, message: &str) {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            target: target.to_string(),
            message: message.to_string(),
        };
        
        // Write to file
        if let Ok(mut writer) = self.file_writer.lock() {
            let _ = writeln!(writer, "{}", entry.formatted());
            let _ = writer.flush();
        }
        
        // Store in memory for TUI
        if let Ok(mut logs) = self.in_memory_logs.lock() {
            logs.push_back(entry);
            if logs.len() > self.max_memory_logs {
                logs.pop_front();
            }
        }
    }
    
    pub fn get_logs(&self) -> Vec<LogEntry> {
        if let Ok(logs) = self.in_memory_logs.lock() {
            logs.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    // Fallback logger that does nothing if file creation fails
    pub fn fallback() -> Self {
        // Create a temporary file for fallback
        let temp_file = std::env::temp_dir().join("ironchat_fallback.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(temp_file)
            .unwrap_or_else(|_| {
                // If even temp file fails, create a dummy file handle
                File::create("/dev/null").unwrap()
            });
        
        Self {
            file_writer: Arc::new(Mutex::new(BufWriter::new(file))),
            in_memory_logs: Arc::new(Mutex::new(VecDeque::new())),
            max_memory_logs: 1000,
        }
    }
    
    pub fn debug(&self, target: &str, message: &str) {
        self.log(LogLevel::Debug, target, message);
    }
    
    pub fn info(&self, target: &str, message: &str) {
        self.log(LogLevel::Info, target, message);
    }
    
    pub fn warn(&self, target: &str, message: &str) {
        self.log(LogLevel::Warn, target, message);
    }
    
    pub fn error(&self, target: &str, message: &str) {
        self.log(LogLevel::Error, target, message);
    }
}

use std::sync::OnceLock;

// Global logger instance - safe using OnceLock
static LOGGER: OnceLock<Arc<IronLogger>> = OnceLock::new();

pub fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    LOGGER.get_or_init(|| {
        IronLogger::new()
            .map(Arc::new)
            .unwrap_or_else(|_| Arc::new(IronLogger::fallback()))
    });
    Ok(())
}

pub fn get_logger() -> Option<Arc<IronLogger>> {
    LOGGER.get().cloned()
}

// Convenience macros to replace tracing
#[macro_export]
macro_rules! iron_debug {
    ($target:expr, $($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.debug($target, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! iron_info {
    ($target:expr, $($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.info($target, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! iron_warn {
    ($target:expr, $($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.warn($target, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! iron_error {
    ($target:expr, $($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.error($target, &format!($($arg)*));
        }
    };
}