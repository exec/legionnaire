# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-08-01

### Security
- **CRITICAL**: Fixed input validation vulnerabilities in IRC message parsing
- **CRITICAL**: Added protection against protocol confusion attacks (HTTP/SMTP commands now rejected)
- **HIGH**: Fixed potential panic conditions due to unsafe array access in CAP message handling
- **MEDIUM**: Enhanced tag section validation to prevent oversized tag attacks
- **MEDIUM**: Added proper validation for IRC prefixes containing spaces

### Fixed
- Non-ASCII characters in message parameters are now properly rejected
- Array bounds checking added to prevent panics on malformed CAP messages
- Oversized tag sections now properly validated before parsing
- Invalid IRC prefixes with embedded spaces are now detected and rejected
- Command validation enhanced to block known non-IRC protocol commands

### Technical Details
- Added ASCII-only enforcement for all IRC message components
- Implemented early tag length validation (8191 byte limit)
- Enhanced `is_valid_command()` function with protocol confusion protection
- Added bounds checking for `message.params[]` access in client.rs
- Strengthened prefix parsing validation

## [0.1.0] - 2025-07-25

### Added
- Initial release of IronChat security-hardened IRCv3 client
- Comprehensive SASL authentication support (PLAIN, EXTERNAL, SCRAM-SHA-256)  
- Modern TLS implementation with certificate verification
- Advanced DoS protection and rate limiting
- IRCv3 capability negotiation
- Terminal-based user interface (TUI)
- Message logging and history
- Fuzz testing infrastructure
- Security-focused architecture and design