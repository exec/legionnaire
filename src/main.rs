use ironchat::{IronClient, IrcUi, IrcTui, Config};
use ironchat::client::IrcConfig;
use ironchat::config::SaslConfig;
use ironchat::{iron_info, iron_error, iron_warn, iron_debug};
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
    ironchat::logger::init_logger()?;
    
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
                        println!("💡 Try using: \x1b[96mironchat libera --classic\x1b[0m for text-only mode");
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