// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// #[derive(Debug)]
// pub enum EncryptionType {
//     Legacy,
//     Ansible,
//     Nacl,
// }
//
// #[derive(Debug)]
// pub struct KeyFile {
//     pub path: String,
//     pub name: String,
//     pub kind: EncryptionType,
//     pub key: String,
//     pub password: String,
// }
//
// impl KeyFile {
//     pub fn new() -> KeyFile {
//         KeyFile {
//             path: String::from(""),
//             name: String::from(""),
//             kind: EncryptionType::Nacl,
//             key: String::from(""),
//             password: String::from(""),
//         }
//     }
// }
//
// pub fn validate_password(password: &str) -> bool {
//     let min_length = 8;
//
//     if password.len() < min_length {
//         return false;
//     }
//
//     return true;
// }

pub mod error;
use clap::Args;
use error::KeystoreError;

use sp_core::crypto::SecretString;

/// Parameters of the keystore
#[derive(Debug, Clone, Args)]
pub struct KeystoreArgs {
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
