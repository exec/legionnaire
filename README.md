# IronChat

A **security-hardened, modern IRCv3 client** built in Rust with a clean terminal user interface.

## Features

### Core IRC Support
- **IRCv3 Protocol**: Full support for modern IRC with capability negotiation (CAP 3.2)
- **TLS 1.3 Security**: Secure connections with certificate validation using rustls
- **SASL Authentication**: Support for PLAIN, EXTERNAL, and SCRAM-SHA-256 authentication
- **Single-Server Focus**: Clean, minimalist design with one connection per instance

### User Interface
- **Unified Sidebar**: Single sidebar with channels and collapsible user lists
- **Keyboard Navigation**: Navigate sidebar with Up/Down, select with Enter
- **Message Scrolling**: Navigate message history with PageUp/PageDown
- **Tab Completion**: Auto-complete nicknames and commands with Tab
- **Clean Message Display**: Timestamps, nick highlighting, and colored message types
- **Classic Fallback**: Terminal-based UI when TUI is not available

### Usability
- **Smart Configuration**: TOML config with interactive setup wizard
- **Customizable Keybindings**: All shortcuts are user-configurable
- **Service Aliases**: Built-in shortcuts for NickServ (/ns), ChanServ (/cs), etc.
- **Message Activity**: Unread counts and mention highlighting
- **Collapsible UI**: User lists collapse by default to keep sidebar clean

### Security & Quality
- **Input Validation**: Hardened against malformed IRC messages
- **Memory Safety**: Written in Rust with zero unsafe code
- **Certificate Verification**: Strict TLS certificate validation by default
- **No Data Collection**: Privacy-focused with no telemetry

## Installation

```bash
git clone https://github.com/exec/ironchat
cd ironchat
cargo build --release
./target/release/ironchat --setup
```

## Quick Start

1. **First Run**: `ironchat --setup` to configure your servers and preferences
2. **Connect**: `ironchat` to launch with TUI, or `ironchat --classic` for terminal mode
3. **Join Channels**: `/join #channel` or configure auto-join channels in config
4. **Get Help**: Press `Ctrl+h` in TUI mode or type `/help`

## Keyboard Shortcuts

| Action | Default Key | Alternative | Customizable |
|--------|-------------|-------------|--------------|
| Navigate sidebar | Up/Down | - | Fixed |
| Select channel/toggle users | Enter | - | Fixed |
| Scroll messages | PageUp/PageDown | - | Fixed |
| Tab completion | Tab | - | Fixed |
| Toggle help | Ctrl+h | - | ✅ |
| Toggle sidebar | Ctrl+u | - | ✅ |
| Quit | Ctrl+c | - | ✅ |

**Navigation**: Use Up/Down arrows to navigate the sidebar, Enter to select channels or expand/collapse user lists.

## Configuration

Config location: `~/.config/ironchat/config.toml`

```toml
default_server = "Libera Chat"

[[servers]]
name = "Libera Chat"
host = "irc.libera.chat"
port = 6697
tls = true
verify_certificates = true
channels = ["#rust", "#programming"]

[user]
nickname = "yournick"
username = "yournick"
realname = "Your Name"

[keybindings]
toggle_help = "Ctrl+h"
next_tab = "Tab"
scroll_up = "PageUp"
# ... all keys are customizable
```

## Commands

### IRC Commands
- `/join #channel` - Join a channel
- `/part [channel]` - Leave current or specified channel
- `/nick <nickname>` - Change nickname
- `/msg <user> <message>` - Send private message
- `/quit [reason]` - Quit IRC

### Service Shortcuts
- `/ns <command>` - Send to NickServ
- `/cs <command>` - Send to ChanServ
- `/ms <command>` - Send to MemoServ
- `/os <command>` - Send to OperServ
- `/hs <command>` - Send to HostServ
- `/bs <command>` - Send to BotServ

### Client Commands
- `/help` - Show help
- `/raw <command>` - Send raw IRC command

## Roadmap

IronChat follows a clean, minimalist philosophy while including the most useful and widely-adopted IRC features.

### 🟢 Completed Features
- [x] IRCv3 protocol support with capability negotiation
- [x] TLS 1.3 security with certificate validation
- [x] SASL authentication (PLAIN, EXTERNAL, SCRAM-SHA-256)
- [x] Tabbed channel interface
- [x] Message scrolling and navigation
- [x] Tab completion for nicknames and commands
- [x] User list with focus navigation
- [x] Customizable keybindings
- [x] Service command aliases
- [x] TOML configuration with interactive setup
- [x] Activity tracking and mention highlighting
- [x] Classic terminal fallback mode

### 🟡 Planned Features (High Priority)
- [ ] **Message Search** - Search through message history (Ctrl+F)
- [ ] **Message Notifications** - Desktop notifications for mentions
- [ ] **Auto-reconnect** - Automatic reconnection on connection drops
- [ ] **Message Logging** - Save chat history to files
- [ ] **Channel List Browser** - Browse available channels (/list)

### 🔵 Planned Features (Medium Priority)
- [ ] **Timestamps Toggle** - Show/hide message timestamps
- [ ] **Multiple Server Connections** - Connect to multiple networks
- [ ] **Private Message Windows** - Separate tabs for private conversations
- [ ] **Message Formatting** - Support for bold, italic, color codes
- [ ] **Status Bar** - Connection status and current mode display

### 🟣 Advanced Features (Low Priority)
- [ ] **DCC File Transfers** - Send and receive files
- [ ] **Ignore List** - Block messages from specific users
- [ ] **Highlight Words** - Custom keyword highlighting
- [ ] **Client Certificates** - Certificate-based authentication
- [ ] **Away Status** - Set and display away messages

### 🔴 Modern IRC Extensions (Future)
- [ ] **IRCv3 Message Tags** - Support for advanced IRC extensions
- [ ] **Message Reactions** - React to messages with emoji
- [ ] **Message Replies** - Reply to specific messages
- [ ] **OTR Encryption** - Off-the-record messaging

## Development

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
cargo clippy
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

Focus on clean, maintainable code that follows the existing patterns. Security and usability improvements are always welcome.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with [ratatui](https://github.com/tui-rs-revival/ratatui) for the terminal UI
- Uses [rustls](https://github.com/rustls/rustls) for secure TLS connections
- IRC protocol compliance tested against ergochat and Libera Chat

---

**IronChat**: Secure, Modern, Minimalist IRC

### Security-First Design
- **Mandatory TLS 1.3**: Secure connections by default with modern cipher suites
- **Certificate Validation**: Full certificate chain validation with OCSP support
- **SASL Authentication**: Support for PLAIN and EXTERNAL mechanisms with secure credential handling
- **Input Validation**: Comprehensive message validation to prevent injection attacks
- **Memory Safety**: Rust's ownership system prevents buffer overflows and memory corruption

### IRCv3 Compliance
- **CAP 3.2 Negotiation**: Full support for capability negotiation with dynamic updates
- **Message Tags**: Extended message metadata support
- **SASL Authentication**: Standards-compliant authentication with chunking support
- **STS (Strict Transport Security)**: Enforced secure transport policies
- **Batch Processing**: Efficient message batching for history replay
- **Server Time**: Accurate message timestamps for proper ordering

### Modern Architecture
- **Async I/O**: Built on Tokio for high-performance concurrent operations
- **Zero-Copy Parsing**: Efficient message parsing with minimal allocations
- **Structured Logging**: Comprehensive tracing with configurable log levels
- **Error Handling**: Comprehensive error types with context information

## Quick Start

### Basic Usage

```bash
# Set environment variables
export IRC_SERVER="irc.libera.chat"
export IRC_NICK="yournick"
export IRC_CHANNELS="#rust,#security"

# With SASL authentication
export IRC_SASL_USER="yourusername"
export IRC_SASL_PASS="yourpassword"

# Run the client
cargo run
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IRC_SERVER` | IRC server hostname | `irc.libera.chat` |
| `IRC_PORT` | IRC server port | `6697` |
| `IRC_NICK` | Nickname to use | `ironchat` |
| `IRC_CHANNELS` | Comma-separated channel list | (none) |
| `IRC_SASL_USER` | SASL username | (none) |
| `IRC_SASL_PASS` | SASL password | (none) |
| `IRC_SASL_EXTERNAL` | Use EXTERNAL SASL | (none) |
| `IRC_NO_TLS` | ⚠️ Disable TLS | (none) |
| `IRC_NO_CERT_VERIFY` | ⚠️ Disable certificate verification | (none) |

### Programmatic Usage

```rust
use ironchat::{IronClient, IrcConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = IrcConfig {
        server: "irc.libera.chat".to_string(),
        port: 6697,
        nickname: "mybot".to_string(),
        username: "mybot".to_string(),
        realname: "My IRC Bot".to_string(),
        channels: vec!["#rust".to_string()],
        tls_required: true,
        verify_certificates: true,
        ..Default::default()
    };

    let mut client = IronClient::new(config);
    client.with_sasl_plain("username".to_string(), "password".to_string());
    
    client.connect().await?;
    client.run().await?;
    
    Ok(())
}
```

## Security Considerations

### TLS Configuration
- **TLS 1.3 Preferred**: Uses modern protocol with perfect forward secrecy
- **Certificate Validation**: Full chain validation with hostname verification
- **Cipher Suite Selection**: Prioritizes AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- **No Downgrade**: Prevents protocol downgrade attacks

### SASL Security
- **Credential Protection**: Uses the `secrecy` crate to prevent credential leakage
- **TLS Enforcement**: PLAIN mechanism requires active TLS connection
- **Mechanism Selection**: Prefers stronger mechanisms (EXTERNAL > SCRAM > PLAIN)
- **Timeout Protection**: Authentication attempts have strict timeouts

### Input Validation
- **Message Length Limits**: Enforces IRC protocol message length limits
- **Character Validation**: Rejects non-ASCII and control characters
- **Command Validation**: Validates IRC commands against allowed patterns
- **Parameter Limits**: Prevents excessive parameter counts

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   IronClient    │────│ SecureConnection│────│  TLS Transport  │
│   (main API)    │    │  (IRC protocol) │    │   (rustls)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│CapabilityHandler│    │ MessageParser   │
│ (IRCv3 caps)    │    │ (protocol msgs) │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│SaslAuthenticator│    │  ErrorHandling  │
│ (authentication)│    │  (comprehensive)│
└─────────────────┘    └─────────────────┘
```

### Key Design Principles

1. **Security by Default**: All connections use TLS, certificate validation enabled
2. **Fail Securely**: Errors result in connection termination rather than degraded security
3. **Explicit Configuration**: Security-relevant options must be explicitly disabled
4. **Comprehensive Validation**: All input is validated before processing
5. **Resource Limits**: Strict limits prevent resource exhaustion attacks

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific test module
cargo test message::tests
```

## Benchmarks

```bash
# Run performance benchmarks
cargo bench

# Profile memory usage
cargo build --release
valgrind --tool=massif ./target/release/ironchat
```

## Contributing

1. All code must pass `cargo clippy` without warnings
2. Security-relevant changes require security review
3. New features should include comprehensive tests
4. Follow the existing error handling patterns
5. Document public APIs with examples

## Security Reporting

If you discover a security vulnerability, please report it privately to the maintainers. Do not open public issues for security-related problems.

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) for async I/O
- TLS provided by [rustls](https://github.com/rustls/rustls)
- IRCv3 specifications from [IRCv3 Working Group](https://ircv3.net/)
- Security guidance from [OWASP](https://owasp.org/) and [Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS)