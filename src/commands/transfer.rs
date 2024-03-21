use clap::Parser;
use subxt::{OnlineClient, SubstrateConfig};
use subxt_signer::{
    bip39::Mnemonic,
    sr25519::{dev, Keypair},
};

use crate::commands::error::CommandError;
use crate::config;
use crate::subtensor::interface::api;

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

    let dest = dev::bob().public_key().into();

    let balance_transfer_tx = api::tx().balances().transfer(dest, 10_000);

    // test phrase
    let phrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    let mnemonic = Mnemonic::parse(phrase).unwrap();
    let from = Keypair::from_phrase(&mnemonic, None).unwrap();
    let account_id = from.public_key().to_account_id().to_string();
    let public_key = from.public_key().into();
    println!("Account ID: {:?}", account_id);

    let storage_query = api::storage().system().account(&public_key);

    let result = client
        .storage()
        .at_latest()
        .await
        .map_err(CommandError::Invalid)?
        .fetch(&storage_query)
        .await;

    println!("balance: {:?}", result);
    match result {
        Ok(data) => match data {
            Some(data) => {
                println!("Balance: {:?}", data.data.free);
            }
            None => {
                println!("No data found");
            }
        },
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&balance_transfer_tx, &from)
        .await
        .map_err(CommandError::Invalid)?
        .wait_for_finalized_success()
        .await
        .map_err(CommandError::Invalid)?;

    let transfer_event = events
        .find_first::<api::balances::events::Transfer>()
        .map_err(CommandError::Invalid)?;
    if let Some(event) = transfer_event {
        println!("Balance transfer success: {event:?}");
    }

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
