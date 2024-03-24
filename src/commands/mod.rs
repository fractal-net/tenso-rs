pub mod create_coldkey;
pub mod error;
pub mod stake;
pub mod transfer;

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct CliArgs {
    // Path to config file
    #[arg(
        long = "config_path",
        value_name = "FILE_PATH",
        help = "Specifies the path to the configuration file",
        global = true
    )]
    pub config_path: Option<String>,

    // Path to key files
    #[arg(
        long = "key_path",
        value_name = "DIR_PATH",
        help = "Defines the path to the directory containing key files",
        global = true
    )]
    pub key_path: Option<PathBuf>,

    // Subtensor endpoint
    #[arg(
        short = 'e',
        long = "subtensor_endpoint",
        value_name = "URL",
        global = true,
        help = "URL of the Subtensor endpoint"
    )]
    pub subtensor_endpoint: Option<String>,

    // coldkey
    #[arg(
        long = "coldkey",
        value_name = "STRING",
        help = "Specifies the coldkey to use",
        global = true
    )]
    pub coldkey: Option<String>,

    // hotkey
    #[arg(
        long = "hotkey",
        value_name = "STRING",
        help = "Specifies the hotkey to use",
        global = true
    )]
    pub hotkey: Option<String>,
}
