use legionnaire::{IronClient, IrcUi, IrcTui, Config, Bouncer, BouncerConfig};
use legionnaire::client::IrcConfig;
use legionnaire::config::SaslConfig;
use legionnaire::{iron_info, iron_error, iron_warn, iron_debug};
use legionnaire::cli::{CliHandler, CliCommand};
use legion_protocol::IrcMessage;
use std::env;
use std::panic;
use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM, SIGWINCH};
use signal_hook_tokio::Signals;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration profile to use (e.g., libera, work, testing)
    config_name: Option<String>,
    
    /// Use configuration setup wizard
    #[arg(long)]
    setup: bool,
    
    /// Show configuration file location
    #[arg(long)]
    config_path: bool,
    
    /// Server name from config to connect to
    #[arg(short, long)]
    server: Option<String>,
    
    /// Use classic terminal UI instead of TUI
    #[arg(long)]
    classic: bool,
    
    /// Disable DoS protection (not recommended)
    #[arg(long)]
    no_dos_protection: bool,
    
    /// DoS protection level: default, high-volume, small, or dev
    #[arg(long, value_name = "LEVEL")]
    dos_protection: Option<String>,
    
    /// Show DoS protection statistics
    #[arg(long)]
    dos_stats: bool,
    
    /// Enable testing mode (non-interactive, scriptable)
    #[arg(long)]
    test_mode: bool,
    
    /// Commands to execute in testing mode (one per argument)
    #[arg(long = "test-cmd", value_name = "COMMAND")]
    test_commands: Vec<String>,
    
    /// Session ID for test commands (allows multiple test instances)
    #[arg(long, value_name = "ID")]
    test_session: Option<String>,
    
    /// Timeout for testing mode in seconds
    #[arg(long, default_value = "30")]
    test_timeout: u64,
    
    /// Run in bouncer daemon mode
    #[arg(long)]
    bouncer: bool,
    
    /// Bouncer listen address
    #[arg(long, default_value = "127.0.0.1")]
    bouncer_addr: String,
    
    /// Bouncer listen port  
    #[arg(long, default_value = "6697")]
    bouncer_port: u16,
    
    /// CLI mode - execute a single command
    #[command(subcommand)]
    cli: Option<CliCommand>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up panic handler to clean terminal on panic
    panic::set_hook(Box::new(|_| {
        // Reset terminal state if panic occurs
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture
        );
    }));

    // Set up signal handling for clean terminal cleanup on SIGINT/SIGTERM and SIGWINCH
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGWINCH]).unwrap();
    let signals_handle = signals.handle();
    
    // Spawn signal handler task
    let signal_task = tokio::spawn(async move {
        use futures::StreamExt;
        let mut signals = signals;
        while let Some(signal) = signals.next().await {
            match signal {
                SIGWINCH => {
                    // Window resize - just ignore, let TUI handle it
                    iron_debug!("main", "Window resize detected, ignoring");
                }
                SIGINT | SIGTERM => {
                    // Clean up terminal on signal
                    let _ = crossterm::terminal::disable_raw_mode();
                    let _ = crossterm::execute!(
                        std::io::stdout(),
                        crossterm::terminal::LeaveAlternateScreen,
                        crossterm::event::DisableMouseCapture
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });

    let args = Args::parse();
    
    // Initialize custom logger system
    legionnaire::logger::init_logger()?;
    
    // Show config path if requested
    if args.config_path {
        match Config::config_path() {
            Ok(path) => {
                println!("Configuration file location: {}", path.display());
                if path.exists() {
                    println!("Status: File exists");
                } else {
                    println!("Status: File does not exist (will use defaults or create on setup)");
                }
            }
            Err(e) => {
                eprintln!("Error determining config path: {}", e);
            }
        }
        return Ok(());
    }

    iron_info!("main", "Starting IronChat - Security-Hardened IRCv3 Client");

    // Handle CLI mode
    if let Some(cli_command) = args.cli {
        // In CLI mode, we execute a single command and exit
        let server_config = if let Some(profile) = args.config_name {
            Config::load_profile(&profile).ok().and_then(|c| c.get_server(args.server.as_deref()).map(|sc| sc.to_irc_config()))
        } else {
            None
        };
        
        let mut cli_handler = CliHandler::new(server_config);
        cli_handler.execute(cli_command).await?;
        return Ok(());
    }
    
    // Handle bouncer daemon mode
    if args.bouncer {
        iron_info!("main", "Starting bouncer daemon on {}:{}", args.bouncer_addr, args.bouncer_port);
        
        // Create bouncer config
        let bouncer_config = BouncerConfig {
            listen_addr: args.bouncer_addr,
            listen_port: args.bouncer_port,
            password: "".to_string(),  // TODO: Add password arg
            use_tls: false,
            max_clients: 10,
            history_size: 5000,
            auto_replay: true,
            keepalive_interval: 60,
        };
        
        // Create IRC config for the bouncer's server connection
        let irc_config = if let Some(profile) = args.config_name {
            Config::load_profile(&profile).ok()
                .and_then(|c| c.get_server(args.server.as_deref()).map(|sc| sc.to_irc_config()))
                .unwrap_or_else(|| IrcConfig::default())
        } else {
            IrcConfig::default()
        };
        
        // Create and start bouncer
        let mut bouncer = Bouncer::new(bouncer_config, irc_config);
        bouncer.start().await?;
        
        iron_info!("main", "Bouncer daemon started successfully");
        
        // Keep running until interrupted
        tokio::signal::ctrl_c().await?;
        
        iron_info!("main", "Shutting down bouncer daemon");
        
        return Ok(());
    }

    // Load or create config
    let app_config = if args.setup {
        Config::interactive_setup().await?
    } else if let Some(profile_name) = &args.config_name {
        // Load specific profile
        match Config::load_profile(profile_name) {
            Ok(config) => {
                println!("Loaded profile: {}", profile_name);
                config
            }
            Err(_) => {
                eprintln!("Profile '{}' not found. Available profiles:", profile_name);
                match Config::discover_profiles() {
                    Ok(profiles) => {
                        if profiles.is_empty() {
                            eprintln!("  No profiles found. Run with --setup to create one.");
                            std::process::exit(1);
                        } else {
                            for profile in profiles {
                                eprintln!("  {}", profile);
                            }
                            std::process::exit(1);
                        }
                    }
                    Err(_) => {
                        eprintln!("  Could not scan for profiles");
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        // No profile specified - try interactive selection or fallback
        match Config::discover_profiles() {
            Ok(profiles) => {
                if profiles.is_empty() {
                    // No profiles exist, check for legacy config or env vars first
                    let config_path = Config::config_path().unwrap();
                    if config_path.exists() {
                        Config::load()?
                    } else if env::var("IRC_SERVER").is_ok() {
                        println!("Using environment variables for configuration");
                        Config::default()
                    } else {
                        // No legacy config and no env vars - use interactive profile selection which will create defaults
                        Config::interactive_profile_selection().await?
                    }
                } else if profiles.len() == 1 {
                    // Only one profile, load it automatically
                    let profile_name = &profiles[0];
                    println!("Loading profile: {}", profile_name);
                    Config::load_profile(profile_name)?
                } else {
                    // Multiple profiles available, let user choose
                    Config::interactive_profile_selection().await?
                }
            }
            Err(_) => {
                // Fallback to legacy behavior
                match Config::load() {
                    Ok(config) => config,
                    Err(_) => {
                        if env::var("IRC_SERVER").is_ok() {
                            println!("Using environment variables for configuration");
                            Config::default()
                        } else {
                            println!("No configuration found. Starting setup wizard...");
                            Config::interactive_setup().await?
                        }
                    }
                }
            }
        }
    };

    // Apply DoS protection level if specified
    let mut app_config = app_config;
    if let Some(dos_level) = &args.dos_protection {
        app_config.set_dos_protection_for_server(dos_level);
        println!("DoS protection set to: {} level", dos_level);
        println!("  Rate limit: {} msg/sec", app_config.dos_protection.message_rate_limit);
        println!("  Max connections: {}", app_config.dos_protection.max_connections);
        println!("  Memory per connection: {}MB", app_config.dos_protection.max_memory_per_connection / 1024 / 1024);
    }

    // Check if we're using env vars exclusively
    let (irc_config, display_info) = if env::var("IRC_SERVER").is_ok() && app_config.servers.is_empty() {
        // Pure env var mode
        let config = use_env_vars()?;
        let info = format!("{} ({}:{})", config.server, config.server, config.port);
        (config, info)
    } else {
        // Config file mode
        let server_config = app_config.get_server(args.server.as_deref())
            .ok_or("No server configuration found")?;

        // Convert to IrcConfig
        let mut irc_config = IrcConfig {
            server: server_config.host.clone(),
            port: server_config.port,
            nickname: app_config.user.nickname.clone(),
            username: app_config.user.username.clone()
                .unwrap_or_else(|| app_config.user.nickname.clone()),
            realname: app_config.user.realname.clone()
                .unwrap_or_else(|| app_config.user.nickname.clone()),
            tls_required: server_config.tls,
            verify_certificates: server_config.verify_certificates,
            channels: server_config.channels.clone(),
            ..IrcConfig::default() // Use defaults for timeout fields
        };

        // Override with any env vars if present (for testing)
        if let Ok(server) = env::var("IRC_SERVER") {
            irc_config.server = server;
        }
        if let Ok(port_str) = env::var("IRC_PORT") {
            irc_config.port = port_str.parse().unwrap_or(6697);
        }
        if let Ok(nick) = env::var("IRC_NICK") {
            irc_config.nickname = nick.clone();
            irc_config.username = nick.clone();
        }
        if env::var("IRC_NO_CERT_VERIFY").is_ok() {
            irc_config.verify_certificates = false;
            println!("⚠️  WARNING: Certificate verification disabled!");
        }

        let info = format!("{} ({}:{})", server_config.name, server_config.host, server_config.port);
        
        // Configure SASL if present
        let mut client = IronClient::new(irc_config.clone());
        if let Some(sasl) = &server_config.sasl {
            match sasl {
                SaslConfig::Plain { username, password } => {
                    iron_info!("main", "Configuring SASL PLAIN authentication");
                    client.with_sasl_plain(username.clone(), password.clone());
                }
                SaslConfig::External => {
                    iron_info!("main", "Configuring SASL EXTERNAL authentication");
                    client.with_sasl_external();
                }
                SaslConfig::ScramSha256 { username, password } => {
                    iron_info!("main", "Configuring SASL SCRAM-SHA-256 authentication");
                    client.with_sasl_scram_sha256(username.clone(), password.clone());
                }
            }
        }
        
        (irc_config, info)
    };

    println!("\nConnecting to {}", display_info);
    if let Ok(config_path) = Config::config_path() {
        if config_path.exists() {
            println!("Configuration: {}", config_path.display());
        }
    }
    println!();

    // Handle testing mode early if requested
    if args.test_mode {
        return run_test_mode(irc_config, args).await;
    }

    // Create client (DoS protection handling temporarily simplified for fuzzing setup)
    let mut client = if args.no_dos_protection {
        iron_warn!("main", "DoS protection disabled - this is not recommended for production use!");
        IronClient::new(irc_config.clone())
    } else {
        iron_info!("main", "DoS protection configuration loaded but using basic client for now");
        IronClient::new(irc_config.clone())
    };

    // Check for env var SASL (backward compatibility)
    if let (Ok(username), Ok(password)) = (env::var("IRC_SASL_USER"), env::var("IRC_SASL_PASS")) {
        iron_info!("main", "Configuring SASL PLAIN authentication from env");
        client.with_sasl_plain(username, password);
    } else if env::var("IRC_SASL_EXTERNAL").is_ok() {
        iron_info!("main", "Configuring SASL EXTERNAL authentication from env");
        client.with_sasl_external();
    }

    // Show DoS stats if requested
    if args.dos_stats && !args.no_dos_protection {
        println!("\n📊 DoS Protection Configuration:");
        println!("  • Rate limit: {} msgs/sec", app_config.dos_protection.message_rate_limit);
        println!("  • Max connections: {}", app_config.dos_protection.max_connections);
        println!("  • Max memory per connection: {} MB", app_config.dos_protection.max_memory_per_connection / (1024 * 1024));
        println!("  • Bandwidth limit: {} KB/s", app_config.dos_protection.max_bandwidth_per_connection / 1024);
        println!("  • CPU monitoring: {}", if app_config.dos_protection.enable_cpu_monitoring { "enabled" } else { "disabled" });
        println!();
    }

    if args.classic {
        // Use classic terminal UI
        let mut ui = IrcUi::new(client);
        if let Err(e) = ui.start().await {
            iron_error!("main", "UI error: {}", e);
            std::process::exit(1);
        }
    } else {
        // Connect first with full logging, then initialize TUI
        println!("\x1b[96m🔗 Initiating connection to \x1b[93m{}\x1b[96m...\x1b[0m", client.server_name());
        
        match client.connect().await {
            Ok(_) => {
                println!("\x1b[92m✅ Connection established! Initializing TUI...\x1b[0m");
                
                // Wait for all initialization logs to complete before TUI takes over
                std::thread::sleep(std::time::Duration::from_millis(200));
                
                // Now create TUI but don't connect again
                match IrcTui::new_connected(client, &app_config) {
                    Ok(mut tui) => {
                        // TUI has taken over - all future logs should be suppressed or redirected
                        let result = tui.start_with_existing_connection().await;
                        // Ensure cleanup happens before checking result
                        drop(tui);
                        
                        if let Err(e) = result {
                            iron_error!("main", "TUI error: {}", e);
                            // Reset terminal state before exiting
                            let _ = crossterm::terminal::disable_raw_mode();
                            let _ = crossterm::execute!(
                                std::io::stdout(),
                                crossterm::terminal::LeaveAlternateScreen,
                                crossterm::event::DisableMouseCapture
                            );
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        iron_error!("main", "❌ Failed to create TUI: {}", e);
                        println!("⚠️  TUI initialization failed, this may be due to remote server message burst");
                        println!("💡 Try using: \x1b[96mlegionnaire libera --classic\x1b[0m for text-only mode");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                iron_error!("main", "❌ Connection failed: {}", e);
                println!("\x1b[91m❌ Connection failed. Check the logs above for details.\x1b[0m");
                std::process::exit(1);
            }
        }
    }

    // Clean up signal handler
    signals_handle.close();
    signal_task.abort();
    
    iron_info!("main", "IronChat shutdown complete");
    Ok(())
}

fn use_env_vars() -> Result<IrcConfig, Box<dyn std::error::Error>> {
    let mut config = IrcConfig::default();
    
    if let Ok(server) = env::var("IRC_SERVER") {
        config.server = server;
    }
    
    if let Ok(port_str) = env::var("IRC_PORT") {
        config.port = port_str.parse().unwrap_or(6697);
    }
    
    if let Ok(nick) = env::var("IRC_NICK") {
        config.nickname = nick;
        config.username = config.nickname.clone();
    }
    
    if let Ok(channels) = env::var("IRC_CHANNELS") {
        config.channels = channels.split(',').map(|s| s.trim().to_string()).collect();
    }

    if env::var("IRC_NO_TLS").is_ok() {
        config.tls_required = false;
        if config.port == 6697 {
            config.port = 6667;
        }
        println!("⚠️  WARNING: Running without TLS encryption!");
    }

    if env::var("IRC_NO_CERT_VERIFY").is_ok() {
        config.verify_certificates = false;
        println!("⚠️  WARNING: Certificate verification disabled!");
    }

    Ok(config)
}

async fn run_test_mode(irc_config: IrcConfig, args: Args) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::time::{timeout, Duration};
    use tokio::io::{self, AsyncBufReadExt, BufReader};
    
    println!("🧪 Starting IronChat in Testing Mode");
    println!("Session ID: {}", args.test_session.as_deref().unwrap_or("default"));
    println!("Timeout: {} seconds", args.test_timeout);
    println!("Commands to execute: {}", args.test_commands.len());
    
    // Create and connect client
    let mut client = IronClient::new(irc_config);
    
    // Configure SASL if provided via env vars
    if let (Ok(username), Ok(password)) = (std::env::var("IRC_SASL_USER"), std::env::var("IRC_SASL_PASS")) {
        iron_info!("test_mode", "Configuring SASL PLAIN authentication from env");
        client.with_sasl_plain(username, password);
    } else if std::env::var("IRC_SASL_EXTERNAL").is_ok() {
        iron_info!("test_mode", "Configuring SASL EXTERNAL authentication from env");
        client.with_sasl_external();
    }
    
    println!("🔗 Connecting to {}...", client.server_name());
    
    // Connect with timeout (use most of the timeout for connection)
    let connect_timeout = Duration::from_secs(args.test_timeout.saturating_sub(2));
    let connect_result = timeout(connect_timeout, client.connect()).await;
    
    match connect_result {
        Ok(Ok(_)) => {
            println!("✅ Connected successfully!");
        }
        Ok(Err(e)) => {
            eprintln!("❌ Connection failed: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("❌ Connection timed out");
            return Err("Connection timeout".into());
        }
    }
    
    // Wait for registration to complete
    println!("⏳ Waiting for registration...");
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    println!("🤖 Executing test commands...");
    
    // Execute predefined commands
    for (i, cmd) in args.test_commands.iter().enumerate() {
        println!("[{}] > {}", i + 1, cmd);
        
        if let Err(e) = execute_test_command(&mut client, cmd).await {
            eprintln!("❌ Command failed: {}", e);
        }
        
        // Brief pause between commands
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    // If no predefined commands, enter interactive command mode
    if args.test_commands.is_empty() {
        println!("📝 Interactive command mode (type 'quit' to exit):");
        println!("Available commands:");
        println!("  join <channel>     - Join a channel");
        println!("  part <channel>     - Leave a channel");
        println!("  msg <target> <msg> - Send message");
        println!("  notice <target>    - Send notice");
        println!("  nick <nick>        - Change nickname");
        println!("  raw <command>      - Send raw IRC command");
        println!("  quit               - Disconnect and exit");
        
        // Message handling is built into the client now
        let _session_id = args.test_session.clone().unwrap_or_else(|| "default".to_string());
        
        // Interactive command loop with timeout for automated testing
        let stdin = io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        let interactive_timeout = Duration::from_secs(1); // Short timeout for automated tests
        
        loop {
            print!("test> ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            
            // Use timeout to prevent hanging in automated tests
            let line_result = timeout(interactive_timeout, lines.next_line()).await;
            
            match line_result {
                Ok(Ok(Some(line))) => {
                    let line = line.trim();
                    
                    if line.is_empty() {
                        continue;
                    }
                    
                    if line == "quit" {
                        break;
                    }
                    
                    if let Err(e) = execute_test_command(&mut client, line).await {
                        eprintln!("❌ Command failed: {}", e);
                    }
                }
                Ok(Ok(None)) => {
                    // EOF
                    break;
                }
                Ok(Err(_)) => {
                    // IO error
                    break;
                }
                Err(_) => {
                    // Timeout - likely an automated test with no input
                    println!("⏰ No input received - likely automated test, exiting gracefully");
                    break;
                }
            }
        }
    } else {
        // For non-interactive mode, listen for messages briefly
        let listen_duration = Duration::from_secs(5);
        println!("👂 Listening for responses for {} seconds...", listen_duration.as_secs());
        
        let session_id = args.test_session.unwrap_or_else(|| "default".to_string());
        let listen_result = timeout(listen_duration, async {
            // Messages are handled internally by the client now
            println!("[{}] Test commands executed", session_id);
        }).await;
        
        if listen_result.is_err() {
            println!("⏰ Listening timeout reached");
        }
    }
    
    println!("🔌 Disconnecting...");
    if let Err(e) = client.disconnect().await {
        eprintln!("⚠️  Disconnect error: {}", e);
    }
    
    println!("✅ Test session complete");
    Ok(())
}

async fn execute_test_command(client: &mut IronClient, cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    
    if parts.is_empty() {
        return Err("Empty command".into());
    }
    
    match parts[0].to_lowercase().as_str() {
        "join" => {
            if parts.len() < 2 {
                return Err("Usage: join <channel>".into());
            }
            let channel = parts[1];
            client.join_channel(channel).await?;
            println!("  Joined {}", channel);
        }
        
        "part" => {
            if parts.len() < 2 {
                return Err("Usage: part <channel>".into());
            }
            let channel = parts[1];
            client.part_channel(channel, Some("Test session")).await?;
            println!("  Parted {}", channel);
        }
        
        "msg" | "privmsg" => {
            if parts.len() < 3 {
                return Err("Usage: msg <target> <message>".into());
            }
            let target = parts[1];
            let message = parts[2..].join(" ");
            client.send_privmsg(target, &message).await?;
            println!("  Sent message to {}: {}", target, message);
        }
        
        "notice" => {
            if parts.len() < 3 {
                return Err("Usage: notice <target> <message>".into());
            }
            let target = parts[1];
            let message = parts[2..].join(" ");
            let notice_msg = IrcMessage::new("NOTICE")
                .with_params(vec![target.to_string(), message.to_string()]);
            client.send_message(&notice_msg).await?;
            println!("  Sent notice to {}: {}", target, message);
        }
        
        "nick" => {
            if parts.len() < 2 {
                return Err("Usage: nick <nickname>".into());
            }
            let nick = parts[1];
            let nick_msg = IrcMessage::new("NICK")
                .with_params(vec![nick.to_string()]);
            client.send_message(&nick_msg).await?;
            println!("  Changed nick to {}", nick);
        }
        
        "raw" => {
            if parts.len() < 2 {
                return Err("Usage: raw <irc_command>".into());
            }
            let raw_cmd = parts[1..].join(" ");
            client.send_raw(&raw_cmd).await?;
            println!("  Sent raw: {}", raw_cmd);
        }
        
        _ => {
            return Err(format!("Unknown command: {}", parts[0]).into());
        }
    }
    
    Ok(())
}