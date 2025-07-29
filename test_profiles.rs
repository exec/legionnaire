use ironchat::Config; #[tokio::main] async fn main() { Config::create_default_profiles().unwrap(); println\!("Done"); }
