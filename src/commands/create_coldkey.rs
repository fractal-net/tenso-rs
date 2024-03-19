use crate::{commands::error::CommandError, config, keystore::KeystoreArgs};

use bip39::Mnemonic;
use clap::Parser;
use sc_cli::{
    utils::PublicFor,
    utils::{print_from_uri, SeedFor},
    with_crypto_scheme, CryptoScheme, OutputType,
};
use serde_json::json;
use sp_core::{
    crypto::{
        unwrap_or_default_ss58_version, ExposeSecret, SecretString, Ss58AddressFormat, Ss58Codec,
    },
    hexdisplay::HexDisplay,
    Pair,
};
use sp_runtime::{traits::IdentifyAccount, MultiSigner};

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

    get_new_keyfile_json::<sp_core::sr25519::Pair>(
        &phrase,
        password,
        Some(Ss58AddressFormat::custom(5)),
    );

    // print_from_uri::<sp_core::sr25519::Pair>(
    //     &phrase,
    //     password,
    //     Some(Ss58AddressFormat::custom(5)),
    //     OutputType::Json,
    // );

    Ok(())
}

/// get new keyfile

pub fn get_new_keyfile_json<Pair>(
    uri: &str,
    password: Option<SecretString>,
    network_override: Option<Ss58AddressFormat>,
) -> Result<serde_json::Value, CommandError>
where
    Pair: sp_core::Pair,
    Pair::Public: Into<MultiSigner>,
{
    let password = password.as_ref().map(|s| s.expose_secret().as_str());

    if let Ok((pair, seed)) = Pair::from_phrase(uri, password) {
        let public_key = pair.public();
        let network_override = unwrap_or_default_ss58_version(network_override);
        let ss58_public_key = public_key.to_ss58check_with_version(network_override);

        let json = json!({
            "secretPhrase": uri,
            "secretSeed": format_seed::<Pair>(seed),
            "publicKey": format_public_key::<Pair>(public_key.clone()),
            "accountId": format_account_id::<Pair>(public_key),
            "ss58Address": ss58_public_key,
        });

        return Ok(json);
    }

    Err(CommandError::InvalidMnemonic(
        "invalid mnemonic while creating keyfile".into(),
    ))
}

/// formats seed as hex
fn format_seed<P: sp_core::Pair>(seed: SeedFor<P>) -> String {
    format!("0x{}", HexDisplay::from(&seed.as_ref()))
}

/// formats public key as hex
fn format_public_key<P: sp_core::Pair>(public_key: PublicFor<P>) -> String {
    format!("0x{}", HexDisplay::from(&public_key.as_ref()))
}

/// formats public key as accountId as hex
fn format_account_id<P: sp_core::Pair>(public_key: PublicFor<P>) -> String
where
    PublicFor<P>: Into<MultiSigner>,
{
    format!(
        "0x{}",
        HexDisplay::from(&public_key.into().into_account().as_ref())
    )
}
