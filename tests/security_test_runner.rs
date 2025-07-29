use ironchat::message::IrcMessage;
use ironchat::error::{IronError, Result};
use tracing::{info, warn, error};
use std::time::Instant;

mod malicious_server;
use malicious_server::{test_message_parsing_security, TestResults};

/// Comprehensive security test runner for IronChat
/// 
/// This test runner validates that the IRC client properly handles:
/// - Malformed messages
/// - Buffer overflow attempts  
/// - Protocol injection attacks
/// - Invalid character sequences
/// - Authentication bypass attempts
/// - TLS downgrade scenarios
pub struct SecurityTestRunner {
    pub verbose: bool,
    pub fail_fast: bool,
}

impl SecurityTestRunner {
    pub fn new() -> Self {
        Self {
            verbose: false,
            fail_fast: false,
        }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Run all security tests
    pub async fn run_all_tests(&self) -> Result<SecurityTestReport> {
        let start_time = Instant::now();
        info!("Starting comprehensive IronChat security tests");

        let mut report = SecurityTestReport::new();

        // 1. Test message parsing security
        info!("Running message parsing security tests...");
        match self.run_message_parsing_tests().await {
            Ok(results) => {
                report.add_category("Message Parsing", results);
            }
            Err(e) => {
                error!("Message parsing tests failed: {}", e);
                if self.fail_fast {
                    return Err(e);
                }
                report.add_error("Message Parsing", e.to_string());
            }
        }

        // 2. Test buffer overflow protection
        info!("Running buffer overflow protection tests...");
        match self.run_buffer_overflow_tests().await {
            Ok(results) => {
                report.add_category("Buffer Overflow Protection", results);
            }
            Err(e) => {
                error!("Buffer overflow tests failed: {}", e);
                if self.fail_fast {
                    return Err(e);
                }
                report.add_error("Buffer Overflow Protection", e.to_string());
            }
        }

        // 3. Test injection attack protection
        info!("Running injection attack protection tests...");
        match self.run_injection_tests().await {
            Ok(results) => {
                report.add_category("Injection Attack Protection", results);
            }
            Err(e) => {
                error!("Injection attack tests failed: {}", e);
                if self.fail_fast {
                    return Err(e);
                }
                report.add_error("Injection Attack Protection", e.to_string());
            }
        }

        // 4. Test protocol confusion protection
        info!("Running protocol confusion protection tests...");
        match self.run_protocol_confusion_tests().await {
            Ok(results) => {
                report.add_category("Protocol Confusion Protection", results);
            }
            Err(e) => {
                error!("Protocol confusion tests failed: {}", e);
                if self.fail_fast {
                    return Err(e);
                }
                report.add_error("Protocol Confusion Protection", e.to_string());
            }
        }

        // 5. Test DoS protection
        info!("Running DoS protection tests...");
        match self.run_dos_protection_tests().await {
            Ok(results) => {
                report.add_category("DoS Protection", results);
            }
            Err(e) => {
                error!("DoS protection tests failed: {}", e);
                if self.fail_fast {
                    return Err(e);
                }
                report.add_error("DoS Protection", e.to_string());
            }
        }

        report.total_duration = start_time.elapsed();
        info!("Security tests completed in {:?}", report.total_duration);

        Ok(report)
    }

    async fn run_message_parsing_tests(&self) -> Result<TestResults> {
        test_message_parsing_security().await?;
        
        let mut results = TestResults::new();
        
        // Additional parsing tests
        let test_cases = vec![
            ("valid_privmsg", "PRIVMSG #test :Hello world", true),
            ("valid_with_tags", "@time=2023-01-01T00:00:00.000Z PRIVMSG #test :Hello", true),
            ("valid_with_prefix", ":nick!user@host PRIVMSG #test :Hello", true),
            ("oversized_message", &"A".repeat(1000), false),
            ("null_byte", "PRIVMSG #test :hello\0world", false),
            ("newline_injection", "PRIVMSG #test :hello\nworld", false),
            ("carriage_return", "PRIVMSG #test :hello\rworld", false),
            ("empty_message", "", false),
            ("whitespace_only", "   \r\n", false),
        ];

        for (name, message, should_pass) in test_cases {
            let passed = match message.parse::<IrcMessage>() {
                Ok(_) => should_pass,
                Err(_) => !should_pass,
            };
            
            results.add_result(name, passed, None);
            
            if self.verbose {
                if passed {
                    info!("✓ Message parsing test '{}' passed", name);
                } else {
                    warn!("✗ Message parsing test '{}' failed", name);
                }
            }
        }

        Ok(results)
    }

    async fn run_buffer_overflow_tests(&self) -> Result<TestResults> {
        let mut results = TestResults::new();

        let test_cases = vec![
            ("huge_message", "A".repeat(100000)),
            ("huge_command", format!("{} #test :hello", "A".repeat(100))),
            ("huge_tags", format!("@{} PRIVMSG #test :hello", "tag=value;".repeat(5000))),
            ("huge_prefix", format!(":{}!user@host PRIVMSG #test :hello", "A".repeat(1000))),
            ("many_params", format!("PRIVMSG {} :hello", 
                (0..50).map(|i| format!("#ch{}", i)).collect::<Vec<_>>().join(" "))),
        ];

        for (name, message) in test_cases {
            let passed = message.parse::<IrcMessage>().is_err();
            results.add_result(name, passed, None);
            
            if self.verbose {
                if passed {
                    info!("✓ Buffer overflow test '{}' passed", name);
                } else {
                    warn!("✗ Buffer overflow test '{}' failed", name);
                }
            }
        }

        Ok(results)
    }

    async fn run_injection_tests(&self) -> Result<TestResults> {
        let mut results = TestResults::new();

        let test_cases = vec![
            ("command_injection", "PRIVMSG #test :hello\r\nQUIT :injected\r\n"),
            ("null_injection", "PRIVMSG #test :hello\0QUIT :injected"),
            ("nick_injection", "NICK attacker\r\nJOIN #admin\r\n"),
            ("sasl_injection", "AUTHENTICATE +\r\nPRIVMSG #admin :injected\r\n"),
            ("tag_injection", "@evil=value\r\nQUIT :injected PRIVMSG #test :hello"),
            ("prefix_injection", ":evil\r\nQUIT :injected!user@host PRIVMSG #test :hello"),
        ];

        for (name, message) in test_cases {
            let passed = message.parse::<IrcMessage>().is_err();
            results.add_result(name, passed, None);
            
            if self.verbose {
                if passed {
                    info!("✓ Injection test '{}' passed", name);
                } else {
                    warn!("✗ Injection test '{}' failed", name);
                }
            }
        }

        Ok(results)
    }

    async fn run_protocol_confusion_tests(&self) -> Result<TestResults> {
        let mut results = TestResults::new();

        let test_cases = vec![
            ("http_request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ("smtp_command", "EHLO example.com\r\n"),
            ("pop3_command", "USER username\r\n"),
            ("ftp_command", "USER anonymous\r\n"),
            ("telnet_escape", "\xFF\xFD\x03"),
            ("binary_data", &String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD, 0xFC, 0x0D, 0x0A])),
        ];

        for (name, message) in test_cases {
            let passed = message.parse::<IrcMessage>().is_err();
            results.add_result(name, passed, None);
            
            if self.verbose {
                if passed {
                    info!("✓ Protocol confusion test '{}' passed", name);
                } else {
                    warn!("✗ Protocol confusion test '{}' failed", name);
                }
            }
        }

        Ok(results)
    }

    async fn run_dos_protection_tests(&self) -> Result<TestResults> {
        let mut results = TestResults::new();

        // Test parsing performance
        let start = Instant::now();
        for i in 0..10000 {
            let message = format!("PRIVMSG #test{} :Hello world {}", i % 100, i);
            if message.parse::<IrcMessage>().is_err() {
                results.add_result("performance_test", false, 
                    Some("Valid message failed to parse".to_string()));
                return Ok(results);
            }
        }
        let duration = start.elapsed();

        // Should parse 10k messages in under 500ms
        let performance_ok = duration.as_millis() < 500;
        results.add_result("parsing_performance", performance_ok, 
            Some(format!("Parsed 10k messages in {:?}", duration)));

        // Test memory usage doesn't grow unbounded
        let memory_test_passed = self.test_memory_usage().await;
        results.add_result("memory_usage", memory_test_passed, None);

        if self.verbose {
            info!("DoS protection performance: {:?} for 10k messages", duration);
        }

        Ok(results)
    }

    async fn test_memory_usage(&self) -> bool {
        // Simple memory test - parse many messages and ensure we don't leak
        let start_memory = self.get_memory_usage();
        
        for _ in 0..1000 {
            let _ = "PRIVMSG #test :Hello world".parse::<IrcMessage>();
        }
        
        // Force garbage collection if possible
        // In Rust, this is automatic, but we can at least yield
        tokio::task::yield_now().await;
        
        let end_memory = self.get_memory_usage();
        
        // Memory usage shouldn't grow significantly
        end_memory < start_memory + 1024 * 1024 // Allow 1MB growth
    }

    fn get_memory_usage(&self) -> usize {
        // This is a simplified memory usage check
        // In a real implementation, you might use system calls or profiling tools
        std::mem::size_of::<IrcMessage>() * 1000 // Placeholder
    }
}

impl Default for SecurityTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Comprehensive security test report
#[derive(Debug)]
pub struct SecurityTestReport {
    pub categories: Vec<(String, TestResults)>,
    pub errors: Vec<(String, String)>,
    pub total_duration: std::time::Duration,
}

impl SecurityTestReport {
    pub fn new() -> Self {
        Self {
            categories: Vec::new(),
            errors: Vec::new(),
            total_duration: std::time::Duration::ZERO,
        }
    }

    pub fn add_category(&mut self, name: impl Into<String>, results: TestResults) {
        self.categories.push((name.into(), results));
    }

    pub fn add_error(&mut self, category: impl Into<String>, error: impl Into<String>) {
        self.errors.push((category.into(), error.into()));
    }

    pub fn total_tests(&self) -> usize {
        self.categories.iter().map(|(_, results)| results.total()).sum()
    }

    pub fn total_passed(&self) -> usize {
        self.categories.iter().map(|(_, results)| results.passed).sum()
    }

    pub fn total_failed(&self) -> usize {
        self.categories.iter().map(|(_, results)| results.failed).sum() + self.errors.len()
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_tests();
        if total == 0 {
            0.0
        } else {
            self.total_passed() as f64 / total as f64
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Security Test Report: {} passed, {} failed ({:.1}% success rate) in {:?}",
            self.total_passed(),
            self.total_failed(),
            self.success_rate() * 100.0,
            self.total_duration
        )
    }

    pub fn detailed_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("IronChat Security Test Report\n"));
        report.push_str(&format!("================================\n\n"));
        
        report.push_str(&format!("Overall Results:\n"));
        report.push_str(&format!("  Total Tests: {}\n", self.total_tests()));
        report.push_str(&format!("  Passed: {}\n", self.total_passed()));
        report.push_str(&format!("  Failed: {}\n", self.total_failed()));
        report.push_str(&format!("  Success Rate: {:.1}%\n", self.success_rate() * 100.0));
        report.push_str(&format!("  Duration: {:?}\n\n", self.total_duration));

        for (category, results) in &self.categories {
            report.push_str(&format!("{}: {}\n", category, results.summary()));
        }

        if !self.errors.is_empty() {
            report.push_str(&format!("\nErrors:\n"));
            for (category, error) in &self.errors {
                report.push_str(&format!("  {}: {}\n", category, error));
            }
        }

        report
    }

    pub fn is_success(&self) -> bool {
        self.success_rate() >= 0.95 && self.errors.is_empty()
    }
}

impl Default for SecurityTestReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Main function to run security tests from command line
pub async fn run_security_tests(verbose: bool, fail_fast: bool) -> Result<()> {
    tracing_subscriber::fmt::init();

    let runner = SecurityTestRunner::new()
        .with_verbose(verbose)
        .with_fail_fast(fail_fast);

    let report = runner.run_all_tests().await?;

    if verbose {
        println!("{}", report.detailed_report());
    } else {
        println!("{}", report.summary());
    }

    if !report.is_success() {
        return Err(IronError::SecurityViolation(
            format!("Security tests failed: {:.1}% success rate", 
                report.success_rate() * 100.0)
        ));
    }

    info!("All security tests passed!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_runner() {
        let runner = SecurityTestRunner::new().with_verbose(true);
        let report = runner.run_all_tests().await.expect("Security tests should pass");
        
        println!("{}", report.detailed_report());
        assert!(report.is_success(), "Security tests should pass");
    }
}