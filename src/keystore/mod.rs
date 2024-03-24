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

pub mod cli;
pub mod encryption;
pub mod error;

use error::KeystoreError;

use sc_cli::{utils::PublicFor, utils::SeedFor};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::{
    crypto::{
        unwrap_or_default_ss58_version, ExposeSecret, SecretString, Ss58AddressFormat, Ss58Codec,
    },
    hexdisplay::HexDisplay,
};
use sp_runtime::{traits::IdentifyAccount, MultiSigner};
use std::{fs, os::unix::fs::PermissionsExt};
use std::{fs::Permissions, path::PathBuf};

use self::encryption::EncryptionType;

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    account_id: String,
    public_key: String,
    secret_phrase: Option<String>,
    secret_seed: Option<String>,
    ss58_address: String,

    #[serde(skip_serializing)]
    name: String,
    #[serde(skip_serializing)]
    password: Option<String>,
}

impl Keystore {
    pub fn new<Pair>(
        name: &str,
        uri: &str,
        password: Option<SecretString>,
        network_override: Option<Ss58AddressFormat>,
    ) -> Result<Self, KeystoreError>
    where
        Pair: sp_core::Pair,
        Pair::Public: Into<MultiSigner>,
    {
        if let Ok((pair, seed)) = Pair::from_phrase(uri, None) {
            let public_key = pair.public();
            let network_override = unwrap_or_default_ss58_version(network_override);
            let ss58_address = public_key.to_ss58check_with_version(network_override);

            Ok(Keystore {
                secret_phrase: Some(uri.to_owned()),
                secret_seed: Some(format_seed::<Pair>(seed)),
                public_key: format_public_key::<Pair>(public_key.clone()),
                account_id: format_account_id::<Pair>(public_key),
                ss58_address,

                name: name.to_string(),
                password: password
                    .as_ref()
                    .map(|s| s.expose_secret().as_str())
                    .map(|s| s.to_string()),
            })
        } else {
            Err(KeystoreError::InvalidMnemonic(
                "Invalid mnemonic while creating keyfile".into(),
            ))
        }
    }

    pub fn new_from_disk(
        path: &PathBuf,
        password: Option<SecretString>,
    ) -> Result<Self, KeystoreError> {
        let encrypted = fs::read(path.join("coldkey"))
            .map_err(|e| KeystoreError::Io(e))?
            .to_vec();

        let password = password
            .as_ref()
            .map(|s| s.expose_secret().as_str())
            .map(|s| s.to_string())
            .unwrap();

        let decrypted = encryption::decrypt(&encrypted, &password, EncryptionType::Nacl)?;

        let decrypted_str =
            std::str::from_utf8(&decrypted).map_err(|_| KeystoreError::NoPasswordProvided)?;

        let keystore: Keystore =
            serde_json::from_str(&decrypted_str).map_err(|e| KeystoreError::JsonError(e))?;

        Ok(keystore)
    }

    pub fn to_json(&self) -> Result<serde_json::Value, KeystoreError> {
        Ok(json!(self))
    }

    pub fn save_unencrypted_without_secrets_to_file(
        &self,
        path: &PathBuf,
    ) -> Result<(), KeystoreError> {
        let json = serde_json::json!({
            "accountId": self.account_id,
            "publicKey": self.public_key,
            // Explicitly specify the type for None values as Option<String>
            "secretPhrase": None::<Option<String>>,
            "secretSeed": None::<Option<String>>,
            "ss58Address": self.ss58_address,
        })
        .to_string();

        let full_path = path.join("coldkeypub.txt");
        fs::write(&full_path, json).map_err(KeystoreError::Io);
        fs::set_permissions(&path, Permissions::from_mode(0o600)).map_err(KeystoreError::Io)?;
        Ok(())
    }

    pub fn save_unencrypted_with_secrets_to_file(
        &self,
        path: &PathBuf,
    ) -> Result<(), KeystoreError> {
        let json = self.to_json()?.to_string();
        fs::write(path, json).map_err(|e| KeystoreError::Io(e));
        fs::set_permissions(&path, Permissions::from_mode(0o600)).map_err(KeystoreError::Io)?;
        Ok(())
    }

    pub fn save_encrypted_with_secrets_to_file(&self, path: &PathBuf) -> Result<(), KeystoreError> {
        let json = self.to_json()?.to_string();
        if self.password.is_none() {
            return Err(KeystoreError::NoPasswordProvided);
        }

        let pw = self.password.as_ref().unwrap();
        let encrypted = encryption::encrypt(&json, pw, EncryptionType::Nacl)?;

        let full_path = path.join("coldkey");

        fs::write(&full_path, encrypted).map_err(|e| KeystoreError::Io(e))?;
        fs::set_permissions(&full_path, Permissions::from_mode(0o600))
            .map_err(KeystoreError::Io)?;
        Ok(())
    }
}

pub fn create_keyfile_directory(path: &PathBuf) -> Result<(), KeystoreError> {
    fs::create_dir_all(path).map_err(KeystoreError::Io)
}

pub fn validate_wordcount(num_words: Option<usize>) -> Result<usize, KeystoreError> {
    let words = match num_words {
        Some(words_count) if [12, 15, 18, 21, 24].contains(&words_count) => Ok(words_count),
        Some(_) => Err(KeystoreError::WordCount),
        None => Ok(12),
    };

    return words;
}

pub fn validate_password(password: &str) -> bool {
    let min_length = 8;

    if password.len() < min_length {
        return false;
    }

    return true;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password() {
        assert_eq!(validate_password("passwor"), false);
        assert_eq!(validate_password("password123"), true);
    }

    #[test]
    fn test_validate_wordcount() {
        assert_eq!(validate_wordcount(Some(12)).unwrap(), 12);
        assert_eq!(validate_wordcount(Some(15)).unwrap(), 15);
        assert_eq!(validate_wordcount(Some(18)).unwrap(), 18);
        assert_eq!(validate_wordcount(Some(21)).unwrap(), 21);
        assert_eq!(validate_wordcount(Some(24)).unwrap(), 24);
        assert!(validate_wordcount(Some(25)).is_err());
        assert_eq!(validate_wordcount(None).unwrap(), 12);
    }
}
