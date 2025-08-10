# Legionnaire IRC Client - User Guide

A comprehensive guide to using Legionnaire IRC client for both beginners and power users.

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [User Interface](#user-interface)
3. [Basic IRC Usage](#basic-irc-usage)
4. [Advanced Features](#advanced-features)
5. [Security and Privacy](#security-and-privacy)
6. [Plugins and Bots](#plugins-and-bots)
7. [Troubleshooting](#troubleshooting)
8. [Configuration Reference](#configuration-reference)

## Installation and Setup

### System Requirements

- **Operating System**: Linux, macOS, Windows, or any platform supported by Rust
- **Memory**: Minimum 50MB RAM, recommended 100MB+
- **Storage**: 20MB for installation, additional space for logs and cache
- **Network**: Internet connection for IRC servers

### Installation Methods

#### Method 1: From Source (Most Flexible)
```bash
# Prerequisites: Install Rust from https://rustup.rs/
git clone https://github.com/exec/legionnaire.git
cd legionnaire
cargo build --release
sudo cp target/release/legionnaire /usr/local/bin/
```

#### Method 2: Package Managers
```bash
# Arch Linux
yay -S legionnaire-git

# Homebrew (macOS)
brew install legionnaire

# Cargo (Rust package manager)
cargo install legionnaire
```

#### Method 3: Pre-built Binaries
Download from [GitHub Releases](https://github.com/exec/legionnaire/releases) and extract to your PATH.

### First-Time Configuration

Run the interactive setup wizard:
```bash
legionnaire --setup
```

This will configure:
- Your IRC identity (nickname, username, real name)
- Server connections with popular presets
- Security settings (TLS, certificate verification)
- Plugin preferences

### Manual Configuration

Edit the configuration file directly:
- **Linux**: `~/.config/legionnaire/config.toml`
- **macOS**: `~/Library/Application Support/legionnaire/config.toml`  
- **Windows**: `%APPDATA%\legionnaire\config.toml`

Example minimal configuration:
```toml
[user]
nickname = "my_nick"
username = "my_user"  
realname = "My Real Name"

[[servers]]
name = "libera"
host = "irc.libera.chat"
port = 6697
tls = true
channels = ["#rust", "#general"]
```

## User Interface

### TUI Mode (Terminal User Interface)

The default mode provides a full-featured chat interface:

```
┌─ Legionnaire IRC Client ─────────────────────────────┐
│ Channels    │ Chat: #rust                            │
│ #rust   [42]│ 14:32 <alice> Hey everyone!           │
│ #general [5]│ 14:33 <bob> How's the project going?  │
│ @alice      │ 14:34 <alice> Making good progress    │
│ @charlie    │                                        │
│             │                                        │
│             │                                        │
│─────────────┼────────────────────────────────────────│
│ Input: Type your message here...                     │
└──────────────────────────────────────────────────────┘
```

#### TUI Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between channels and input |
| `Ctrl+N` | Next channel |
| `Ctrl+P` | Previous channel |
| `Ctrl+L` | Clear current channel |
| `Page Up/Down` | Scroll message history |
| `F1` | Show help |
| `Ctrl+C` | Quit application |

### CLI Mode

For scripting and one-off commands:
```bash
# Send message to channel
legionnaire send "#rust" "Hello everyone!"

# Send private message  
legionnaire send "alice" "Private message"

# Join channels
legionnaire join "#rust,#general"

# Get channel info
legionnaire info "#rust"
```

### Bouncer Mode

Run a persistent IRC connection:
```bash
# Start bouncer daemon
legionnaire --bouncer --config bouncer.toml

# Connect TUI to bouncer
legionnaire --connect-bouncer

# Multiple clients can connect to same bouncer
```

## Basic IRC Usage

### Connecting to Networks

#### Popular IRC Networks

**Libera Chat** (FOSS communities)
```toml
[[servers]]
name = "libera"
host = "irc.libera.chat"  
port = 6697
tls = true
channels = ["#libera", "#rust", "#linux"]
```

**OFTC** (Open Source projects)
```toml
[[servers]]
name = "oftc"
host = "irc.oftc.net"
port = 6697  
tls = true
channels = ["#debian", "#kernelnewbies"]
```

### Essential IRC Commands

#### Connection Commands
```
/connect [server]       - Connect to a server
/disconnect             - Disconnect from current server
/reconnect             - Reconnect to current server
/quit [message]        - Quit IRC with optional message
```

#### Channel Commands
```
/join #channel         - Join a channel
/part #channel [msg]   - Leave channel with optional message
/topic #channel [text] - View or set channel topic
/names #channel        - List users in channel
/list [pattern]        - List channels matching pattern
```

#### User Commands  
```
/nick newnick          - Change your nickname
/whois nickname        - Get information about user
/msg nickname message  - Send private message
/me action             - Send action message (/me waves)
```

#### Channel Management (if you have permissions)
```
/kick user [reason]    - Kick user from channel
/ban user              - Ban user from channel
/mode #channel +o user - Give operator status
/mode #channel +v user - Give voice status
```

### Message Formatting

Legionnaire supports IRC formatting codes:

```
Bold: **text** or \x02text\x02
Italic: *text* or \x1Dtext\x1D  
Underline: __text__ or \x1Ftext\x1F
Color: \x03foreground,background or \x034text for red
Reset: \x0F
```

Example:
```
Hello **bold** *italic* __underlined__ text!
```

### Understanding IRC Etiquette

1. **Read channel topic**: `/topic #channel` shows rules and info
2. **Don't repeat messages**: IRC users can see your message history  
3. **Use private messages for off-topic**: Keep channels focused
4. **Respect channel operators**: They maintain order
5. **No advertising/spam**: Most channels prohibit unsolicited promotion
6. **Use pastebin for long code**: Don't flood channels with code blocks

## Advanced Features

### Multi-Server Configuration

Connect to multiple IRC networks simultaneously:

```toml
# Work IRC server
[[servers]]
name = "work"
host = "irc.company.com"
port = 6697
tls = true
verify_certificates = true
channels = ["#general", "#dev-team", "#announcements"]

[servers.sasl]
type = "plain"
username = "work_username"

# Community IRC server  
[[servers]]
name = "libera"
host = "irc.libera.chat"
port = 6697
tls = true
channels = ["#rust", "#programming", "#linux"]

[servers.sasl]
type = "plain" 
username = "community_nickname"
```

### SASL Authentication

Authenticate with NickServ before joining channels:

```toml
[servers.sasl]
type = "plain"              # or "external", "scram-sha-256"
username = "registered_nick"
# Password stored securely via credential manager
```

Supported SASL mechanisms:
- **PLAIN**: Username/password (most common)
- **EXTERNAL**: Client certificate authentication
- **SCRAM-SHA-256**: Secure challenge-response

### Channel Profiles

Create profiles for different use cases:

```toml
[profiles.work]
servers = ["work"]
plugins = ["security-alerts", "meeting-bot"]

[profiles.gaming]  
servers = ["rizon", "quakenet"]
plugins = ["game-notifications"]

[profiles.development]
servers = ["libera", "oftc"]  
plugins = ["github-integration", "paste-helper"]
```

Use profiles:
```bash
legionnaire --profile work
legionnaire --profile gaming
```

### Message Filtering and Highlights

Configure message highlighting:

```toml
[highlighting]
# Highlight mentions of your nick
highlight_nick = true

# Custom highlight words
highlight_words = ["urgent", "meeting", "deployment"]

# Highlight patterns (regex)
highlight_patterns = [
    "bug #\\d+",           # Bug numbers
    "@here|@channel",      # Discord-style mentions  
    "legionnaire"          # Project name
]

# Filter out noise
filter_joins = true        # Hide join/part messages
filter_quits = true        # Hide quit messages  
filter_modes = false       # Show mode changes
```

### Logging and History

Configure message logging:

```toml
[logging]
enabled = true
directory = "~/.local/share/legionnaire/logs"
format = "daily"           # daily, weekly, monthly
max_files = 30            # Keep last 30 log files
include_timestamps = true
include_server_messages = false
```

Access logs:
```bash
# Search logs
legionnaire logs search "keyword" --channel "#rust" --date "2024-01-15"

# Export logs  
legionnaire logs export "#rust" --format json --start "2024-01-01"
```

## Security and Privacy

### End-to-End Encryption (E2EE)

Legionnaire supports E2EE for private conversations and channels:

```bash
# Load E2EE plugin
legionnaire --plugin e2ee

# In TUI mode:
/e2ee init                 # Generate your key pair
/e2ee pubkey               # Show your public key
/e2ee trust alice <pubkey> # Trust another user's key
/e2ee secure #private     # Enable E2EE for channel
```

#### E2EE Key Management
```bash
# Export your private key (backup)
/e2ee export-key backup.key

# Import private key  
/e2ee import-key backup.key

# List trusted keys
/e2ee list-keys

# Revoke compromised key
/e2ee revoke-key alice
```

### Secure Credential Storage

Legionnaire stores sensitive data securely:

- **Linux**: GNOME Keyring / KDE Wallet (via Secret Service)
- **macOS**: Keychain  
- **Windows**: Credential Manager
- **Fallback**: Encrypted file with master password

```bash
# View stored credentials
legionnaire credentials list

# Delete credential
legionnaire credentials delete sasl:irc.example.com:username

# Change master password (encrypted file backend)  
legionnaire credentials change-master-password
```

### DoS Protection and Security

Built-in security features:

```toml
[security]
# Input validation  
strict_input_validation = true
max_message_length = 512
max_name_length = 50

# Rate limiting
enable_rate_limiting = true  
rate_limit_messages_per_minute = 60

# Connection throttling
enable_connection_throttling = true
max_connections_per_ip = 5

# Threat detection
enable_threat_detection = true
log_security_events = true
```

### Privacy Features

```toml
[privacy]
# Don't respond to CTCP VERSION/TIME/PING
ignore_ctcp = true

# Cloak your IP (requires server support)
use_cloak = true

# Don't show real name in WHOIS
hide_realname = false

# Use SASL for authentication (more private than NickServ)
prefer_sasl = true
```

### TLS Configuration

```toml
[servers.tls]
# Require TLS for all connections
required = true

# Verify server certificates  
verify_certificates = true

# Minimum TLS version
min_version = "1.3"

# Client certificate authentication
client_cert = "/path/to/client.crt"
client_key = "/path/to/client.key"
```

## Plugins and Bots

### Available Plugins

#### E2EE Plugin
Provides end-to-end encryption:
```bash
legionnaire --plugin e2ee
```

#### Weather Bot  
Provides weather information:
```bash
# Configure API key during setup
legionnaire --setup

# Usage in channels
!weather London
!weather "New York"  
!weather Tokyo --units metric
```

#### GitHub Integration (Example)
```bash
# Load plugin
legionnaire --plugin github

# Configure in channel  
!github watch owner/repo
!github issues
!github pr 123
```

### Plugin Management

```bash
# List available plugins
legionnaire plugin list

# Load plugin
legionnaire plugin load weather-bot

# Unload plugin  
legionnaire plugin unload weather-bot

# Plugin configuration
legionnaire plugin config weather-bot api_key "your-api-key"
```

### Bot Framework

Legionnaire includes a bot framework for automated responses:

```toml
[bot]
# Enable bot framework
enabled = true

# Command prefix
prefix = "!"

# Allowed channels (empty = all)
channels = ["#bots", "#general"]

# Rate limiting for bots
rate_limit = 10  # commands per minute

# Plugin-specific bot configs
[bot.weather]
api_key_env = "OPENWEATHER_API_KEY"
default_units = "metric"
cache_duration = 3600  # 1 hour
```

### Writing Custom Plugins

Create a simple plugin:

```rust
use legionnaire::plugin::{Plugin, PluginInfo, PluginContext};
use legionnaire::IrcMessage;
use async_trait::async_trait;
use anyhow::Result;

#[derive(Default)]
pub struct HelloPlugin;

#[async_trait]
impl Plugin for HelloPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "hello".to_string(),
            version: "1.0.0".to_string(),
            description: "Says hello to users".to_string(),
        }
    }

    async fn init(&mut self, _context: PluginContext) -> Result<()> {
        println!("Hello plugin initialized!");
        Ok(())
    }

    async fn handle_message(&mut self, message: &IrcMessage) -> Result<()> {
        if message.command == "PRIVMSG" && message.params.len() >= 2 {
            let channel = &message.params[0];
            let text = &message.params[1];
            
            if text.contains("hello") {
                // Respond to greetings
                // (In real plugin, you'd send message back through client)
                println!("Someone said hello in {}", channel);
            }
        }
        Ok(())
    }
}
```

## Troubleshooting

### Common Connection Issues

#### "Connection refused" or "Connection timeout"
- **Check server address and port**: Verify in configuration
- **Test with telnet**: `telnet irc.libera.chat 6667`
- **Check firewall**: Ensure IRC ports (6667, 6697) are open
- **Try different ports**: Some networks have multiple ports

#### "Certificate verification failed"  
- **Update CA certificates**: `sudo apt update && sudo apt install ca-certificates`
- **Check system time**: Ensure correct date/time
- **Temporarily disable verification**: `verify_certificates = false` (insecure)

#### "Nickname already in use"
- **Choose different nick**: Add numbers/underscores
- **Configure alternate nicks**: Set `alt_nicks = ["nick1", "nick2"]`
- **Use SASL authentication**: Authenticate before connecting

### SASL Authentication Issues

#### "SASL authentication failed"
1. **Verify nickname registration**: `/msg NickServ INFO yournick`
2. **Check password**: Ensure correct password in credential store  
3. **Try different mechanism**: Change from `plain` to `scram-sha-256`
4. **Register if needed**: `/msg NickServ REGISTER password email`

#### "SASL mechanism not supported"
- **Check server capabilities**: `/quote CAP LS`
- **Use PLAIN mechanism**: Most widely supported
- **Check server documentation**: Some servers have specific requirements

### Performance Issues

#### High CPU usage
```bash
# Check what's consuming CPU
legionnaire --debug --verbose

# Disable plugins temporarily  
legionnaire --no-plugins

# Check for infinite loops in custom plugins
```

#### High memory usage  
```bash
# Monitor memory usage
legionnaire --monitor

# Clear message history
/clear

# Reduce channel count
# Leave unnecessary channels
```

#### Slow startup
```bash  
# Skip plugin loading
legionnaire --no-plugins

# Use simpler configuration
legionnaire --config minimal.toml

# Check for large log files
ls -la ~/.local/share/legionnaire/logs/
```

### Plugin Issues

#### Plugin won't load
1. **Check plugin availability**: `legionnaire plugin list`  
2. **Verify dependencies**: Some plugins require external tools
3. **Check plugin directory**: Ensure plugins are in correct location
4. **Review error logs**: `legionnaire --debug --plugin myplugin`

#### Bot commands not working
1. **Check bot framework**: Ensure `[bot] enabled = true`
2. **Verify command prefix**: Default is `!`
3. **Check channel permissions**: Some channels block bots
4. **Review rate limiting**: May be temporarily limited

### TUI Issues

#### Display corruption
```bash
# Reset terminal  
reset

# Try different terminal emulator
# Some terminals have better Unicode support

# Check TERM environment variable
echo $TERM
export TERM=xterm-256color
```

#### Colors not working
```bash
# Enable color support
export TERM=xterm-256color

# Check terminal capabilities  
tput colors

# Use monochrome mode if needed
legionnaire --no-color
```

### Debug Mode

Enable detailed logging:
```bash  
# Enable debug output
legionnaire --debug

# Verbose logging
legionnaire --verbose --debug

# Log to file
legionnaire --debug --log-file debug.log

# Trace specific modules
RUST_LOG=legionnaire::plugin=trace legionnaire
```

## Configuration Reference

### Complete Configuration Example

```toml
# User identity
[user]
nickname = "my_nick"
username = "my_user"
realname = "My Real Name"
alt_nicks = ["my_nick_", "my_nick__"]

# Server configurations  
[[servers]]
name = "libera"
host = "irc.libera.chat"
port = 6697
tls = true
verify_certificates = true
auto_connect = true
auto_reconnect = true
reconnect_delay = 30
channels = ["#rust", "#programming"]

# SASL authentication
[servers.sasl]
type = "plain"
username = "registered_nick"
# password stored in credential manager

# Server-specific settings
[servers.settings]
command_delay = 1000       # ms between commands
message_delay = 500        # ms between messages  
flood_protection = true

# Security configuration
[security]
strict_input_validation = true
max_message_length = 512
enable_rate_limiting = true
rate_limit_messages_per_minute = 60
enable_connection_throttling = true
enable_threat_detection = true

# DoS protection
[dos_protection]
enabled = true
max_connections_per_ip = 5
max_channels_per_user = 20
max_nick_changes_per_minute = 3

# Logging configuration
[logging]
enabled = true
directory = "~/.local/share/legionnaire/logs"
format = "daily"
max_files = 30
include_timestamps = true

# Bot framework
[bot]
enabled = true
prefix = "!"
channels = []              # empty = all channels
rate_limit = 10
ignore_self = true

# Plugin configuration
[plugins]
directory = "~/.local/share/legionnaire/plugins"
auto_load = ["e2ee"]      # plugins to load automatically

# TUI appearance
[ui]
theme = "dark"            # dark, light, auto
show_timestamps = true
timestamp_format = "%H:%M"
show_join_part = false
highlight_nick = true
highlight_words = []

# Performance tuning
[performance]
message_buffer_size = 1000
max_backlog = 10000
gc_interval = 300         # seconds
```

### Environment Variables

Override configuration with environment variables:

```bash
# IRC connection
export IRC_NICK="my_nickname"
export IRC_SERVER="irc.libera.chat"  
export IRC_PORT="6697"
export IRC_CHANNELS="#rust,#general"

# Security
export IRC_TLS="true"
export IRC_VERIFY_CERTS="true"

# Credentials  
export IRC_PASSWORD="server_password"
export IRC_SASL_USER="sasl_username"
export IRC_SASL_PASS="sasl_password"

# Bot API keys
export OPENWEATHER_API_KEY="your_weather_api_key"
export GITHUB_TOKEN="your_github_token"

# Advanced
export RUST_LOG="legionnaire=debug"
export LEGIONNAIRE_CONFIG="/custom/path/config.toml"
```

### Configuration Validation

Validate your configuration:
```bash
# Check configuration syntax
legionnaire --check-config

# Test server connectivity
legionnaire --test-connection libera

# Validate all settings
legionnaire --validate
```

---

This user guide covers the essential features of Legionnaire IRC client. For the latest updates and advanced features, check the [official documentation](https://docs.legionnaire.chat) and [GitHub repository](https://github.com/exec/legionnaire).

Happy chatting! 💬