use ironchat::{IronClient, IrcUi, IrcTui, Config};
use ironchat::client::IrcConfig;
use ironchat::config::SaslConfig;
use tracing::{info, error};
use std::env;
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("ironchat=info,tokio_rustls=info")
        .init();

    let args = Args::parse();
    
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

    info!("Starting IronChat - Security-Hardened IRCv3 Client");

    // Load or create config
    let app_config = if args.setup {
        Config::interactive_setup().await?
    } else {
        // Try to load existing config
        match Config::load() {
            Ok(config) => config,
            Err(_) => {
                // No config exists, check for env vars
                if env::var("IRC_SERVER").is_ok() {
                    // Use env vars (backward compatibility)
                    println!("Using environment variables for configuration");
                    // We'll handle env vars after loading config
                    Config::default()
                } else {
                    // Run interactive setup
                    println!("No configuration found. Starting setup wizard...");
                    Config::interactive_setup().await?
                }
            }
        }
    };

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
                    info!("Configuring SASL PLAIN authentication");
                    client.with_sasl_plain(username.clone(), password.clone());
                }
                SaslConfig::External => {
                    info!("Configuring SASL EXTERNAL authentication");
                    client.with_sasl_external();
                }
                SaslConfig::ScramSha256 { username, password } => {
                    info!("Configuring SASL SCRAM-SHA-256 authentication");
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

    let mut client = IronClient::new(irc_config.clone());

    // Check for env var SASL (backward compatibility)
    if let (Ok(username), Ok(password)) = (env::var("IRC_SASL_USER"), env::var("IRC_SASL_PASS")) {
        info!("Configuring SASL PLAIN authentication from env");
        client.with_sasl_plain(username, password);
    } else if env::var("IRC_SASL_EXTERNAL").is_ok() {
        info!("Configuring SASL EXTERNAL authentication from env");
        client.with_sasl_external();
    }

    if args.classic {
        // Use classic terminal UI
        let mut ui = IrcUi::new(client);
        if let Err(e) = ui.start().await {
            error!("UI error: {}", e);
            std::process::exit(1);
        }
    } else {
        // Use TUI with tabs
        match IrcTui::new(client, &app_config) {
            Ok(mut tui) => {
                if let Err(e) = tui.start().await {
                    error!("TUI error: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                error!("Failed to create TUI: {}", e);
                println!("Falling back to classic mode...");
                let fallback_client = IronClient::new(irc_config.clone());
                let mut ui = IrcUi::new(fallback_client);
                if let Err(e) = ui.start().await {
                    error!("UI error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    info!("IronChat shutdown complete");
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