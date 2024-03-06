pub mod stake;
pub mod transfer;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct CliArgs {
    // Path to key files
    #[arg(short = 'p', long = "key_path", value_name = "key_path", global = true)]
    pub key_path: Option<String>,

    // Subtensor endpoint
    #[arg(
        short = 'e',
        long = "subtensor_endpoint",
        value_name = "subtensor_endpoint",
        global = true
    )]
    pub subtensor_endpoint: Option<String>,
}
