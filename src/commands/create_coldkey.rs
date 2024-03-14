use crate::{commands::error::CommandError, config, keystore::KeystoreArgs};

use bip39::Mnemonic;
use clap::Parser;
use sc_cli::{utils::print_from_uri, with_crypto_scheme, CryptoScheme, OutputType};
use sp_core::crypto::Ss58AddressFormat;

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
    let words = match args.num_words {
        Some(words_count) if [12, 15, 18, 21, 24].contains(&words_count) => Ok(words_count),
        Some(_) => Err(CommandError::Input(
            "Invalid number of words given for phrase: must be 12/15/18/21/24".into(),
        )),
        None => Ok(12),
    }?;

    let mnemonic = Mnemonic::generate(words)
        .map_err(|e| CommandError::Input(format!("Mnemonic generation failed: {e}").into()))?;

    let password = args.keystore_params.read_password()?;

    let phrase = mnemonic.words().collect::<Vec<_>>().join(" ");

    with_crypto_scheme!(
        CryptoScheme::Sr25519,
        print_from_uri(
            &phrase,
            password,
            Some(Ss58AddressFormat::custom(5)),
            OutputType::Json,
        )
    );

    Ok(())
}
