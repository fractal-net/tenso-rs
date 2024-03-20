use crate::keystore::error::KeystoreError;
use clap::Args;
use dialoguer::Input;

use sp_core::crypto::SecretString;

/// Parameters of the keystore
#[derive(Debug, Clone, Args)]
pub struct KeystoreArgs {

    /// Use interactive shell for entering the name of the keystore.
    #[arg(long, 
          default_value = "true",
          conflicts_with_all = &["name"],
          help = "Use interactive shell for entering the name of the keystore"
          )
    ]
    pub name_interactive: bool,

    /// Name of the keystore.
    #[arg(
        long,
        conflicts_with_all = &["name_interactive"],
        help = "Name of the keystore"
    )]
    pub name: Option<String>,


    /// Use interactive shell for entering the password used by the keystore.
    #[arg(long, 
          default_value = "true",
          conflicts_with_all = &["password"],
          help = "Use interactive shell for entering the password used by the keystore"
          )
    ]
    pub password_interactive: bool,

    /// Password used by the keystore.
    #[arg(
		long,
		value_parser = secret_string_from_str,
        value_name = "PASSWORD",
		conflicts_with_all = &["password_interactive"],
        help = "Password used by the keystore"
	)]
    pub password: Option<SecretString>,
}

/// Parse a secret string, returning a displayable error.
pub fn secret_string_from_str(s: &str) -> std::result::Result<SecretString, String> {
    std::str::FromStr::from_str(s).map_err(|_| "Could not get SecretString".to_string())
}

impl KeystoreArgs {

    pub fn read_name(&self) -> Result<String, KeystoreError> {

        let (name_interactive, name) = (self.name_interactive, self.name.clone());
        let name = if name_interactive {
            let name = Input::<String>::new()
                .with_prompt("Enter the name of the keystore")
                .interact()
                .map_err(|e| KeystoreError::DialogueError(e))?;

            name
        } else {
            match name {
                Some(name) => name,
                None => return Err(KeystoreError::InvalidName),
            }
        };

        Ok(name)
    }

    pub fn read_password(&self) -> Result<Option<SecretString>, KeystoreError> {
        let (password_interactive, password) = (self.password_interactive, self.password.clone());

        let pass = if password_interactive {
            let password =
                rpassword::prompt_password("Key password: ").map_err(|e| KeystoreError::Io(e))?;
            Some(SecretString::new(password))
        } else {
            password
        };

        Ok(pass)
    }

}

