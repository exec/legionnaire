# Getting Started with Legionnaire IRC Client

Welcome to Legionnaire, a modern, secure, and feature-rich IRC client written in Rust! This guide will help you get up and running quickly.

## 🚀 Quick Start

### Prerequisites

- **Rust 1.75 or later** - [Install Rust](https://rustup.rs/)
- **Git** - For cloning the repository
- **OpenSSL development libraries** (Linux/macOS only)
  - Ubuntu/Debian: `sudo apt install libssl-dev pkg-config`
  - CentOS/RHEL: `sudo yum install openssl-devel`
  - macOS: `brew install openssl`

### Installation

#### From Source (Recommended)
```bash
# Clone the repository
git clone https://github.com/exec/legionnaire.git
cd legionnaire

# Build and install
cargo build --release
cargo install --path .

# Or run directly
cargo run
```

#### Pre-built Binaries
Download the latest release from [GitHub Releases](https://github.com/exec/legionnaire/releases).

## 🎯 First-Time Setup

Legionnaire includes an interactive setup wizard that will guide you through configuration:

```bash
# Run the setup wizard
legionnaire --setup
```

The wizard will help you configure:
- **User Information** (nickname, username, real name)
- **IRC Servers** (with popular presets like Libera Chat, OFTC)
- **Security Preferences** (TLS, certificate verification, E2EE)
- **Plugin Configuration** (bots, extensions)

### Quick Setup with Environment Variables

For automated deployments or Docker containers:

```bash
export IRC_NICK="your_nickname"
export IRC_SERVER="irc.libera.chat"
export IRC_PORT="6697"
export IRC_CHANNELS="#rust,#general"

legionnaire
```

## 🖥️ Usage Modes

Legionnaire supports multiple usage modes:

### 1. TUI Mode (Default)
Full-featured terminal user interface:
```bash
legionnaire
```

Features:
- Multi-channel chat interface
- Real-time message updates
- Built-in help system
- Plugin management

### 2. CLI Mode
For scripting and automation:
```bash
# Send a message
legionnaire send "#channel" "Hello world!"

# Join channels
legionnaire join "#rust,#programming"

# Send direct message
legionnaire send "alice" "Private message"
```

### 3. Bouncer Mode
Persistent IRC connection:
```bash
# Start bouncer daemon
legionnaire --bouncer

# Connect with TUI to running bouncer
legionnaire --connect-bouncer
```

## 🔧 Configuration

### Configuration File Location
- Linux: `~/.config/legionnaire/config.toml`
- macOS: `~/Library/Application Support/legionnaire/config.toml`
- Windows: `%APPDATA%\legionnaire\config.toml`

### Example Configuration
```toml
[user]
nickname = "your_nick"
username = "your_user"
realname = "Your Real Name"

[[servers]]
name = "libera"
host = "irc.libera.chat"
port = 6697
tls = true
verify_certificates = true
channels = ["#rust", "#programming"]

# SASL authentication (optional)
[servers.sasl]
type = "plain"
username = "your_nick"
# Password stored securely, not in config file
```

## 🔐 Security Features

Legionnaire prioritizes security with several built-in features:

### End-to-End Encryption (E2EE)
Enable E2EE for secure messaging:
```bash
# Load E2EE plugin
legionnaire --plugin e2ee

# In TUI: /e2ee init
# Generate and share keys securely
```

### Secure Credential Storage
Passwords and API keys are stored securely:
- **Linux**: Uses Secret Service (GNOME Keyring, KDE Wallet)
- **macOS**: Uses Keychain
- **Windows**: Uses Credential Manager
- **Fallback**: Encrypted file with master password

### DoS Protection
Built-in protection against:
- Rate limiting per client
- Connection throttling per IP
- Malicious pattern detection
- Input validation and sanitization

## 🔌 Plugins and Bots

### Available Plugins

#### E2EE Plugin
```bash
# Enable in setup wizard or load manually
legionnaire --plugin e2ee
```

#### Weather Bot
```bash
# Configure OpenWeatherMap API key
legionnaire --setup  # Will prompt for API key

# Use in channels
!weather London
!weather Tokyo
```

### Plugin Development
Create custom plugins using the Plugin API:

```rust
use legionnaire::plugin::{Plugin, PluginInfo, PluginContext};

#[derive(Default)]
pub struct MyPlugin;

#[async_trait]
impl Plugin for MyPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "my-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "My custom plugin".to_string(),
        }
    }

    async fn init(&mut self, context: PluginContext) -> Result<()> {
        // Plugin initialization
        Ok(())
    }

    async fn handle_message(&mut self, message: &IrcMessage) -> Result<()> {
        // Handle IRC messages
        Ok(())
    }
}
```

## 🌐 Common IRC Networks

Legionnaire includes presets for popular networks:

### Libera Chat
- **Server**: irc.libera.chat:6697 (TLS)
- **Popular Channels**: #libera, #rust, #linux, #programming
- **Registration**: `/msg NickServ REGISTER password email`

### OFTC
- **Server**: irc.oftc.net:6697 (TLS)
- **Popular Channels**: #debian, #kernelnewbies
- **Registration**: `/msg NickServ REGISTER password email`

### Rizon
- **Server**: irc.rizon.net:6697 (TLS)
- **Popular Channels**: #rizon
- **Registration**: `/msg NickServ REGISTER password email`

## 🎮 Basic IRC Commands

### Channel Operations
```
/join #channel          - Join a channel
/part #channel          - Leave a channel
/topic #channel [text]  - View/set channel topic
/names #channel         - List users in channel
```

### User Operations
```
/nick newnick           - Change nickname
/whois nickname         - Get user information
/msg nickname message   - Send private message
```

### Connection
```
/connect [server]       - Connect to server
/disconnect            - Disconnect from server
/quit [message]        - Quit IRC
```

### Legionnaire-Specific
```
/plugin list           - List available plugins
/plugin load name      - Load a plugin
/plugin unload name    - Unload a plugin
/e2ee init            - Initialize E2EE (if plugin loaded)
```

## 🎨 Keyboard Shortcuts (TUI Mode)

- **Ctrl+C** - Quit application
- **Tab** - Switch between input and message panels  
- **Ctrl+N** - Next channel
- **Ctrl+P** - Previous channel
- **Page Up/Down** - Scroll message history
- **Ctrl+L** - Clear current channel
- **F1** - Show help

## 🔍 Troubleshooting

### Connection Issues

**Problem**: Can't connect to server
```bash
# Check DNS resolution
nslookup irc.libera.chat

# Test TLS connection
openssl s_client -connect irc.libera.chat:6697

# Check firewall/proxy settings
```

**Solution**:
1. Verify server address and port
2. Check network connectivity
3. Try without TLS first (port 6667)
4. Check corporate firewall/proxy

### Authentication Issues

**Problem**: SASL authentication failed
1. Verify your registered nickname
2. Check password in credential store
3. Try different SASL mechanisms
4. Register account if needed

### Performance Issues

**Problem**: High CPU/memory usage
```bash
# Check performance metrics
legionnaire --metrics

# Enable performance monitoring
legionnaire --monitor
```

**Solutions**:
1. Disable unnecessary plugins
2. Reduce channel count
3. Check for memory leaks in plugins
4. Update to latest version

### TLS/SSL Issues

**Problem**: Certificate verification failed
```bash
# Temporary bypass (not recommended for production)
legionnaire --insecure

# Check certificate manually
openssl s_client -verify_return_error -connect irc.libera.chat:6697
```

**Solutions**:
1. Update system CA certificates
2. Check system time/timezone
3. Use `verify_certificates = false` in config (insecure)

## 📚 Advanced Features

### Multi-Server Configuration
```toml
[[servers]]
name = "work"
host = "irc.company.com"
port = 6697
tls = true
channels = ["#general", "#dev-team"]

[[servers]]  
name = "community"
host = "irc.libera.chat"
port = 6697
tls = true
channels = ["#rust", "#programming"]
```

### Bouncer Setup
```bash
# Start bouncer on server
legionnaire --bouncer --config bouncer.toml

# Connect from multiple clients
legionnaire --connect-bouncer --host server.example.com
```

### Bot Framework
```rust
use legionnaire::bot::{Bot, BotInfo, BotCommand, BotContext, BotResponse};

#[derive(Default)]
pub struct EchoBot;

#[async_trait]
impl Bot for EchoBot {
    fn info(&self) -> BotInfo {
        BotInfo {
            name: "echo-bot".to_string(),
            description: "Echoes messages".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn commands(&self) -> Vec<BotCommand> {
        vec![BotCommand {
            name: "echo".to_string(),
            description: "Echo a message".to_string(),
            usage: "!echo <message>".to_string(),
        }]
    }

    async fn handle_command(&mut self, context: BotContext) -> Result<BotResponse> {
        Ok(BotResponse::Message(context.args.join(" ")))
    }
}
```

## 🆘 Getting Help

- **Built-in Help**: Press F1 in TUI mode or `/help` command
- **Documentation**: [https://docs.legionnaire.chat](https://docs.legionnaire.chat)
- **Issues**: [GitHub Issues](https://github.com/exec/legionnaire/issues)
- **Discussions**: [GitHub Discussions](https://github.com/exec/legionnaire/discussions)
- **IRC**: #legionnaire on Libera Chat

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/exec/legionnaire.git
cd legionnaire

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin

# Run tests
cargo test

# Run with file watching
cargo watch -x run

# Check code coverage
cargo tarpaulin --html
```

## 📄 License

Legionnaire is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Happy chatting!** 💬

For more detailed documentation, visit the [Legionnaire Documentation](https://docs.legionnaire.chat).