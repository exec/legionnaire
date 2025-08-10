//! Tests for Legion admin command handling

use legionnaire::admin_commands::*;
use legionnaire::legion::{LegionClient, LegionConfig};
use std::time::Duration;

#[tokio::test]
async fn test_command_parsing() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test basic command parsing
    let cmd = handler.parse_command("!kick alice Spamming", "bob", "!test").unwrap();
    assert_eq!(cmd.command, "kick");
    assert_eq!(cmd.params, vec!["alice", "Spamming"]);
    assert_eq!(cmd.user, "bob");
    assert_eq!(cmd.channel, "!test");
    
    // Test command with prefix
    let cmd = handler.parse_command("/ban spammer@* 1d Spam domain", "admin", "!secure").unwrap();
    assert_eq!(cmd.command, "ban");
    assert_eq!(cmd.params, vec!["spammer@*", "1d", "Spam", "domain"]);
    
    // Test alias resolution
    let cmd = handler.parse_command("!k troublemaker", "op", "!chat").unwrap();
    assert_eq!(cmd.command, "kick");
    assert_eq!(cmd.params, vec!["troublemaker"]);
}

#[tokio::test]
async fn test_duration_parsing() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test various duration formats
    assert_eq!(handler.parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(handler.parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(handler.parse_duration("2h").unwrap(), Duration::from_secs(7200));
    assert_eq!(handler.parse_duration("1d").unwrap(), Duration::from_secs(86400));
    assert_eq!(handler.parse_duration("1w").unwrap(), Duration::from_secs(604800));
    
    // Test invalid formats
    assert!(handler.parse_duration("").is_err());
    assert!(handler.parse_duration("abc").is_err());
    assert!(handler.parse_duration("10x").is_err());
}

#[tokio::test]
async fn test_rate_limiting() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig {
        commands_per_minute: 2,
        burst_allowance: 1,
        failed_command_cooldown: Duration::from_millis(100),
    });
    
    // First command should pass
    assert!(handler.check_rate_limit("testuser").await.unwrap());
    handler.update_rate_limit_history("testuser", true).await.unwrap();
    
    // Second command should pass (within burst)
    assert!(handler.check_rate_limit("testuser").await.unwrap());
    handler.update_rate_limit_history("testuser", true).await.unwrap();
    
    // Third command should be rate limited
    assert!(!handler.check_rate_limit("testuser").await.unwrap());
    
    // Different user should not be affected
    assert!(handler.check_rate_limit("otheruser").await.unwrap());
}

#[tokio::test]
async fn test_command_execution_mocks() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test kick command
    let result = handler.process_command("!kick spammer Flooding", "admin", "!general").await.unwrap();
    assert!(result.success);
    assert!(result.broadcast);
    assert!(result.message.contains("Kicked spammer"));
    
    // Test ban command with duration
    let result = handler.process_command("!ban troll@* 24h Trolling", "admin", "!general").await.unwrap();
    assert!(result.success);
    assert!(result.message.contains("Banned troll@*"));
    assert!(result.message.contains("24h"));
    
    // Test topic command
    let result = handler.process_command("!topic Welcome to our secure channel!", "admin", "!general").await.unwrap();
    assert!(result.success);
    assert_eq!(result.message, "Topic for !general set to: Welcome to our secure channel!");
    
    // Test mode command
    let result = handler.process_command("!mode +m", "admin", "!general").await.unwrap();
    assert!(result.success);
    assert!(result.message.contains("moderated"));
    assert!(result.message.contains("enabled"));
}

#[tokio::test]
async fn test_member_list_command() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    let result = handler.process_command("!memberlist", "user", "!test").await.unwrap();
    assert!(result.success);
    
    if let Some(CommandData::MemberList(members)) = result.data {
        assert!(!members.is_empty());
        assert!(members.iter().any(|m| m.role == legion_protocol::MemberRole::Owner));
    } else {
        panic!("Expected member list data");
    }
}

#[tokio::test]
async fn test_help_command() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    let result = handler.process_command("!help", "user", "!test").await.unwrap();
    assert!(result.success);
    
    if let Some(CommandData::HelpInfo(help)) = result.data {
        assert!(!help.is_empty());
        
        // Check for essential commands
        let commands: Vec<&str> = help.iter().map(|h| h.command.as_str()).collect();
        assert!(commands.contains(&"kick"));
        assert!(commands.contains(&"ban"));
        assert!(commands.contains(&"topic"));
        assert!(commands.contains(&"keyrotate"));
    } else {
        panic!("Expected help info data");
    }
}

#[tokio::test]
async fn test_command_aliases() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test all aliases
    let alias_tests = vec![
        ("!k user", "kick"),
        ("!b spammer", "ban"),
        ("!ub spammer", "unban"),
        ("!o helper", "op"),
        ("!do helper", "deop"),
        ("!v newbie", "voice"),
        ("!dv newbie", "devoice"),
        ("!t New topic", "topic"),
        ("!m +i", "mode"),
        ("!kr", "keyrotate"),
        ("!ml", "memberlist"),
        ("!bl", "banlist"),
    ];
    
    for (input, expected_cmd) in alias_tests {
        let cmd = handler.parse_command(input, "user", "!test").unwrap();
        assert_eq!(cmd.command, expected_cmd, "Alias {} should resolve to {}", input, expected_cmd);
    }
}

#[tokio::test]
async fn test_result_formatting() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test member list formatting
    let result = CommandResult {
        success: true,
        message: "Member list".to_string(),
        data: Some(CommandData::MemberList(vec![
            MemberInfo {
                nickname: "alice".to_string(),
                role: legion_protocol::MemberRole::Owner,
                joined_at: std::time::SystemTime::now(),
                is_online: true,
            },
            MemberInfo {
                nickname: "bob".to_string(),
                role: legion_protocol::MemberRole::Member,
                joined_at: std::time::SystemTime::now(),
                is_online: false,
            },
        ])),
        broadcast: false,
    };
    
    let formatted = handler.format_result(&result);
    assert!(formatted.len() > 1);
    assert!(formatted[0] == "Member list");
    assert!(formatted.iter().any(|line| line.contains("alice")));
    assert!(formatted.iter().any(|line| line.contains("●"))); // Online indicator
    assert!(formatted.iter().any(|line| line.contains("○"))); // Offline indicator
}

#[tokio::test]
async fn test_concurrent_command_processing() {
    use tokio::task;
    
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = std::sync::Arc::new(AdminCommandHandler::new(legion_client, RateLimitConfig::default()));
    
    let mut handles = vec![];
    
    // Spawn multiple concurrent command executions
    for i in 0..5 {
        let handler_clone = handler.clone();
        let handle = task::spawn(async move {
            let user = format!("user{}", i);
            let result = handler_clone.process_command("!memberlist", &user, "!test").await.unwrap();
            result.success
        });
        handles.push(handle);
    }
    
    // All should succeed
    for handle in handles {
        assert!(handle.await.unwrap());
    }
}

#[tokio::test]
async fn test_error_handling() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Test empty command
    let result = handler.parse_command("", "user", "!test");
    assert!(result.is_err());
    
    // Test invalid command format
    let result = handler.process_command("!kick", "user", "!test").await.unwrap();
    assert!(!result.success);
    assert!(result.message.contains("Usage"));
    
    // Test unknown command
    let result = handler.process_command("!unknowncmd arg1 arg2", "user", "!test").await.unwrap();
    assert!(!result.success);
    assert!(result.message.contains("Unknown command"));
}

#[tokio::test]
async fn test_complex_ban_scenarios() {
    let legion_client = LegionClient::new(LegionConfig::default()).await.unwrap();
    let handler = AdminCommandHandler::new(legion_client, RateLimitConfig::default());
    
    // Ban with reason only
    let result = handler.process_command("!ban user@example.com Repeated spam", "admin", "!test").await.unwrap();
    assert!(result.success);
    assert!(result.message.contains("permanently"));
    
    // Ban with duration and reason
    let result = handler.process_command("!ban *@spam.com 7d Spam domain", "admin", "!test").await.unwrap();
    assert!(result.success);
    assert!(result.message.contains("7d"));
    
    // Ban with just duration
    let result = handler.process_command("!ban tempuser 1h", "admin", "!test").await.unwrap();
    assert!(result.success);
    assert!(result.message.contains("1h"));
}