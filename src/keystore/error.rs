use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Invalid configuration")]
    Invalid(#[source] figment::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),
}
