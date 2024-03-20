use bip39::Mnemonic;
use clap::Parser;
use sp_core::crypto::Ss58AddressFormat;

use crate::{
    commands::error::CommandError,
    config,
    keystore::{self, cli::KeystoreArgs, Keystore},
};

#[derive(Debug, Parser)]
pub struct CreateColdkeyArgs {
    #[arg(
        long = "length",
        value_name = "INTEGER",
        help = "Specifies the length of the seed phrase in number of words, value must be 12 or 24"
    )]
    pub num_words: Option<usize>,

    #[command(flatten)]
    pub keystore_params: KeystoreArgs,
}

pub fn create_new_coldkey(
    config: &config::Config,
    args: &CreateColdkeyArgs,
) -> Result<(), CommandError> {
    let words = keystore::validate_wordcount(args.num_words)?;

    let mnemonic = Mnemonic::generate(words)
        .map_err(|e| CommandError::Input(format!("Mnemonic generation failed: {e}").into()))?;

    let name = args.keystore_params.read_name()?;

    let password = args.keystore_params.read_password()?;
    let phrase = mnemonic.words().collect::<Vec<_>>().join(" ");

    let keystore = Keystore::new::<sp_core::sr25519::Pair>(
        &name,
        &phrase,
        password,
        Some(Ss58AddressFormat::custom(42)),
    )?;

    let full_path = config.key_path.join(&name);
    println!("Saving keystore to: {:?}", full_path);

    keystore.save_unencrypted_without_secrets_to_file(&full_path)?;

    Ok(())
}
