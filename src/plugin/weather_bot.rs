//! Weather Bot Plugin
//!
//! Example bot that provides weather information using the bot framework.
//! Demonstrates command handling, API integration, and bot plugin architecture.

use crate::bot::{Bot, BotInfo, BotCommand, BotContext, BotResponse};
use crate::plugin::{Plugin, PluginInfo, PluginState, PluginContext};
use async_trait::async_trait;
use legion_protocol::IrcMessage;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::{info, warn, error, debug};

/// Weather bot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeatherBotConfig {
    /// API key for weather service (OpenWeatherMap, etc.)
    pub api_key: String,
    /// Default units (metric, imperial, kelvin)
    pub default_units: String,
    /// Cache duration for weather data in minutes
    pub cache_duration: u64,
    /// Maximum locations per user
    pub max_locations_per_user: usize,
}

impl Default for WeatherBotConfig {
    fn default() -> Self {
        Self {
            api_key: "".to_string(),
            default_units: "metric".to_string(),
            cache_duration: 10,
            max_locations_per_user: 5,
        }
    }
}

/// Weather data cache entry
#[derive(Debug, Clone)]
struct WeatherCacheEntry {
    data: WeatherData,
    cached_at: chrono::DateTime<chrono::Utc>,
}

/// Simplified weather data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WeatherData {
    location: String,
    temperature: f64,
    description: String,
    humidity: u32,
    wind_speed: f64,
    units: String,
}

/// Weather Bot Plugin
pub struct WeatherBotPlugin {
    // Plugin state
    plugin_state: PluginState,
    
    // Bot state
    config: WeatherBotConfig,
    /// Weather data cache
    cache: HashMap<String, WeatherCacheEntry>,
    /// User default locations
    user_locations: HashMap<String, String>, // nick -> default_location
    /// HTTP client for API calls
    client: reqwest::Client,
}

impl WeatherBotPlugin {
    pub fn new() -> Self {
        Self {
            plugin_state: PluginState::Loaded,
            config: WeatherBotConfig::default(),
            cache: HashMap::new(),
            user_locations: HashMap::new(),
            client: reqwest::Client::new(),
        }
    }
    
    /// Fetch weather data from API (mocked for this example)
    async fn fetch_weather(&self, location: &str, units: &str) -> Result<WeatherData> {
        // In a real implementation, this would call a weather API
        // For demo purposes, we'll return mock data
        
        if self.config.api_key.is_empty() {
            return Err(anyhow!("Weather API key not configured"));
        }
        
        debug!("Fetching weather for: {} (units: {})", location, units);
        
        // Mock weather data
        let temperature = match units {
            "imperial" => 72.0,
            "kelvin" => 295.15,
            _ => 22.0, // metric (celsius)
        };
        
        let weather = WeatherData {
            location: location.to_string(),
            temperature,
            description: "Partly cloudy".to_string(),
            humidity: 65,
            wind_speed: 3.5,
            units: units.to_string(),
        };
        
        Ok(weather)
    }
    
    /// Get cached weather or fetch new data
    async fn get_weather(&mut self, location: &str, units: &str) -> Result<WeatherData> {
        let cache_key = format!("{}:{}", location.to_lowercase(), units);
        let now = chrono::Utc::now();
        
        // Check cache first
        if let Some(entry) = self.cache.get(&cache_key) {
            let age = now.signed_duration_since(entry.cached_at);
            if age.num_minutes() < self.config.cache_duration as i64 {
                debug!("Using cached weather for: {}", location);
                return Ok(entry.data.clone());
            }
        }
        
        // Fetch fresh data
        let weather = self.fetch_weather(location, units).await?;
        
        // Update cache
        self.cache.insert(cache_key, WeatherCacheEntry {
            data: weather.clone(),
            cached_at: now,
        });
        
        Ok(weather)
    }
    
    /// Format weather data for IRC
    fn format_weather(&self, weather: &WeatherData) -> String {
        let temp_unit = match weather.units.as_str() {
            "imperial" => "°F",
            "kelvin" => "K",
            _ => "°C",
        };
        
        let speed_unit = match weather.units.as_str() {
            "imperial" => "mph",
            _ => "m/s",
        };
        
        format!(
            "🌤️ {} | {}°{} | {} | Humidity: {}% | Wind: {}{} {}",
            weather.location,
            weather.temperature,
            temp_unit,
            weather.description,
            weather.humidity,
            weather.wind_speed,
            speed_unit,
            if self.cache.contains_key(&format!("{}:{}", weather.location.to_lowercase(), weather.units)) {
                "(cached)"
            } else {
                ""
            }
        )
    }
    
    /// Handle weather command
    async fn handle_weather_command(&mut self, context: &BotContext) -> Result<BotResponse> {
        let location = if context.args.is_empty() {
            // Use user's default location
            self.user_locations.get(&context.sender)
                .ok_or_else(|| anyhow!("No location specified and no default location set"))?
                .clone()
        } else {
            context.args.join(" ")
        };
        
        let units = self.config.default_units.clone();
        
        match self.get_weather(&location, &units).await {
            Ok(weather) => {
                let response = self.format_weather(&weather);
                Ok(BotResponse::Reply(response))
            }
            Err(e) => {
                error!("Weather fetch error: {}", e);
                Ok(BotResponse::Reply(format!("❌ Failed to get weather for '{}': {}", location, e)))
            }
        }
    }
    
    /// Handle set location command
    async fn handle_set_location(&mut self, context: &BotContext) -> Result<BotResponse> {
        if context.args.is_empty() {
            return Ok(BotResponse::Reply("Usage: !setlocation <city, country>".to_string()));
        }
        
        let location = context.args.join(" ");
        let units = self.config.default_units.clone();
        
        // Validate location by trying to fetch weather
        match self.get_weather(&location, &units).await {
            Ok(_) => {
                self.user_locations.insert(context.sender.clone(), location.clone());
                Ok(BotResponse::Reply(format!("✅ Default location set to: {}", location)))
            }
            Err(e) => {
                Ok(BotResponse::Reply(format!("❌ Invalid location '{}': {}", location, e)))
            }
        }
    }
    
    /// Handle forecast command
    async fn handle_forecast_command(&mut self, context: &BotContext) -> Result<BotResponse> {
        // For demo purposes, just show extended info
        let location = if context.args.is_empty() {
            self.user_locations.get(&context.sender)
                .ok_or_else(|| anyhow!("No location specified and no default location set"))?
                .clone()
        } else {
            context.args.join(" ")
        };
        
        let units = self.config.default_units.clone();
        match self.get_weather(&location, &units).await {
            Ok(weather) => {
                let response = format!(
                    "📅 5-Day Forecast for {} | Today: {} | Tomorrow: {} | This feature requires premium API access",
                    weather.location, weather.description, "Sunny"
                );
                Ok(BotResponse::Reply(response))
            }
            Err(e) => {
                Ok(BotResponse::Reply(format!("❌ Failed to get forecast for '{}': {}", location, e)))
            }
        }
    }
}

#[async_trait]
impl Bot for WeatherBotPlugin {
    fn info(&self) -> BotInfo {
        BotInfo {
            name: "weatherbot".to_string(),
            version: "1.0.0".to_string(),
            description: "Provides current weather information and forecasts".to_string(),
            author: "Legion Protocol Contributors".to_string(),
        }
    }
    
    async fn init(&mut self, config: serde_json::Value) -> Result<()> {
        if let Ok(weather_config) = serde_json::from_value::<WeatherBotConfig>(config) {
            self.config = weather_config;
        }
        
        if self.config.api_key.is_empty() {
            warn!("Weather bot started without API key - using mock data");
        } else {
            info!("Weather bot initialized with API key");
        }
        
        Ok(())
    }
    
    fn commands(&self) -> Vec<BotCommand> {
        vec![
            BotCommand {
                name: "weather".to_string(),
                aliases: vec!["w".to_string(), "temp".to_string()],
                description: "Get current weather for a location".to_string(),
                usage: "!weather [location] - Get weather (uses your default if no location given)".to_string(),
                min_args: 0,
                max_args: None,
                admin_only: false,
                allowed_channels: Vec::new(),
                cooldown: 5,
            },
            BotCommand {
                name: "setlocation".to_string(),
                aliases: vec!["setloc".to_string()],
                description: "Set your default weather location".to_string(),
                usage: "!setlocation <city, country> - Set your default location".to_string(),
                min_args: 1,
                max_args: None,
                admin_only: false,
                allowed_channels: Vec::new(),
                cooldown: 30,
            },
            BotCommand {
                name: "forecast".to_string(),
                aliases: vec!["fc".to_string()],
                description: "Get weather forecast for a location".to_string(),
                usage: "!forecast [location] - Get 5-day forecast".to_string(),
                min_args: 0,
                max_args: None,
                admin_only: false,
                allowed_channels: Vec::new(),
                cooldown: 10,
            },
        ]
    }
    
    async fn handle_command(&mut self, context: BotContext) -> Result<BotResponse> {
        match context.command.as_str() {
            "weather" | "w" | "temp" => self.handle_weather_command(&context).await,
            "setlocation" | "setloc" => self.handle_set_location(&context).await,
            "forecast" | "fc" => self.handle_forecast_command(&context).await,
            _ => Ok(BotResponse::Reply("Unknown weather command".to_string())),
        }
    }
    
    async fn on_start(&mut self) -> Result<()> {
        info!("Weather bot started!");
        Ok(())
    }
    
    async fn on_stop(&mut self) -> Result<()> {
        info!("Weather bot stopped!");
        Ok(())
    }
    
    async fn on_tick(&mut self) -> Result<Vec<BotResponse>> {
        // Clean old cache entries
        let now = chrono::Utc::now();
        let cache_limit = chrono::Duration::minutes(self.config.cache_duration as i64);
        
        self.cache.retain(|_, entry| {
            let age = now.signed_duration_since(entry.cached_at);
            age < cache_limit
        });
        
        if self.cache.is_empty() {
            debug!("Weather cache cleaned - no active entries");
        }
        
        Ok(Vec::new())
    }
}

#[async_trait]
impl Plugin for WeatherBotPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "weather-bot".to_string(),
            version: "1.0.0".to_string(),
            description: "Weather information bot using the bot framework".to_string(),
            author: "Legion Protocol Contributors".to_string(),
            capabilities: vec!["bot".to_string(), "weather".to_string()],
        }
    }
    
    async fn init(&mut self, context: PluginContext) -> Result<()> {
        // Initialize as plugin
        self.plugin_state = PluginState::Loaded;
        
        // Initialize bot with plugin config
        Bot::init(self, context.plugin_config).await?;
        
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        self.plugin_state = PluginState::Running;
        
        // Start bot
        Bot::on_start(self).await?;
        
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.plugin_state = PluginState::Stopped;
        
        // Stop bot
        Bot::on_stop(self).await?;
        
        Ok(())
    }
    
    async fn handle_message(&mut self, message: &IrcMessage) -> Result<()> {
        // Let bot framework handle commands
        if let Some(_response) = Bot::handle_message(self, message).await? {
            // In a real implementation, we'd send the response through the IRC client
            debug!("Weather bot would send response for message: {:?}", message);
        }
        
        Ok(())
    }
    
    async fn filter_outgoing(&mut self, _message: &mut IrcMessage) -> Result<bool> {
        Ok(true) // Always allow outgoing messages
    }
    
    fn state(&self) -> PluginState {
        self.plugin_state
    }
    
    async fn handle_command(&mut self, command: &str, args: &[String]) -> Result<String> {
        match command {
            "status" => {
                Ok(format!(
                    "Weather Bot Status:\\n\\\
                     Plugin State: {:?}\\n\\\
                     API Key: {}\\n\\\
                     Cache Entries: {}\\n\\\
                     User Locations: {}\\n\\\
                     Default Units: {}",
                    self.plugin_state,
                    if self.config.api_key.is_empty() { "Not configured" } else { "Configured" },
                    self.cache.len(),
                    self.user_locations.len(),
                    self.config.default_units
                ))
            }
            
            "cache" => {
                if args.is_empty() {
                    Ok(format!("Cache contains {} weather entries", self.cache.len()))
                } else if args[0] == "clear" {
                    let count = self.cache.len();
                    self.cache.clear();
                    Ok(format!("Cleared {} cache entries", count))
                } else {
                    Ok("Usage: cache [clear]".to_string())
                }
            }
            
            _ => Ok(format!("Unknown weather bot command: {}. Available: status, cache", command))
        }
    }
}