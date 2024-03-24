use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum KeystoreError {
    #[error("Invalid configuration")]
    Invalid(#[source] figment::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("Dialogue error")]
    DialogueError(#[from] dialoguer::Error),

    #[error("Invalid word count")]
    WordCount,

    #[error("Invalid name")]
    InvalidName,

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Unsupported encryption type")]
    UnsupportedEncryptionType,

    #[error("No password provided")]
    NoPasswordProvided,

    #[error("Json error")]
    JsonError(#[from] serde_json::Error),
}
