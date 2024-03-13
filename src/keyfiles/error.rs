use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyfileError {
    #[error("Invalid configuration")]
    Invalid(#[source] figment::Error),
}
