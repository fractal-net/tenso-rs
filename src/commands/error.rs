use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Invalid Transfer")]
    Invalid(#[source] subxt::Error),
}
