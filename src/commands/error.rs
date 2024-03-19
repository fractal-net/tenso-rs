use thiserror::Error;

use crate::keystore::error::KeystoreError;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Invalid Transfer")]
    Invalid(#[source] subxt::Error),

    #[error("Invalid input: {0}")]
    Input(String),

    #[error("Keyfile error")]
    KeystoreError(#[from] KeystoreError),
}
