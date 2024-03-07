use clap::Parser;
use subxt::{OnlineClient, SubstrateConfig};

use crate::commands::error::CommandError;
use crate::config;

#[derive(Debug, Parser)]
pub struct TransferArgs {
    // Recipient address
    #[arg(long = "recipient", value_name = "Address of the recipient")]
    pub recipient: String,

    #[arg(long = "amount", value_name = "Amount to transfer")]
    pub amount: Option<u64>,
}

pub async fn transfer(config: &config::Config, args: &TransferArgs) -> Result<(), CommandError> {
    let client = OnlineClient::<SubstrateConfig>::from_url(&config.subtensor_endpoint)
        .await
        .map_err(CommandError::Invalid)?;

    println!(
        "Connected to Substrate endpoint at {}",
        &config.subtensor_endpoint
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_args() {}
}
