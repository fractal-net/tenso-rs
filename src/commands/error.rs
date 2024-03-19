use thiserror::Error;

use crate::keystore::error::KeystoreError;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Invalid Transfer")]
    Invalid(#[source] subxt::Error),

    #[error("Invalid input: {0}")]
    Input(String),

    #[error("Keystore error")]
    KeystoreError(#[from] KeystoreError),

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
}
