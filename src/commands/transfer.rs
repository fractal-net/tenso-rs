use clap::Parser;

use crate::config;

#[derive(Debug, Parser)]
pub struct TransferArgs {
    // Recipient address
    #[arg(long = "recipient", value_name = "Address of the recipient")]
    pub recipient: String,

    #[arg(long = "amount", value_name = "Amount to transfer")]
    pub amount: Option<u64>,
}

pub fn transfer(config: &config::Config, args: &TransferArgs) {}
