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

#[derive(Debug)]
pub enum EncryptionType {
    Legacy,
    Ansible,
    Nacl,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    account_id: String,
    public_key: String,
    secret_phrase: Option<String>,
    secret_seed: Option<String>,
    ss58_address: String,

    password: Option<String>,
}

impl Keystore {
    pub fn new<Pair>(
        uri: &str,
        password: Option<SecretString>,
        network_override: Option<Ss58AddressFormat>,
    ) -> Result<Self, KeystoreError>
    where
        Pair: sp_core::Pair,
        Pair::Public: Into<MultiSigner>,
    {
        let password = password.as_ref().map(|s| s.expose_secret().as_str());
        if let Ok((pair, seed)) = Pair::from_phrase(uri, password) {
            let public_key = pair.public();
            let network_override = unwrap_or_default_ss58_version(network_override);
            let ss58_address = public_key.to_ss58check_with_version(network_override);

            Ok(Keystore {
                secret_phrase: Some(uri.to_owned()),
                secret_seed: Some(format_seed::<Pair>(seed)),
                public_key: format_public_key::<Pair>(public_key.clone()),
                account_id: format_account_id::<Pair>(public_key),
                ss58_address,
                password: password.map(|s| s.to_string()),
            })
        } else {
            Err(KeystoreError::InvalidMnemonic(
                "Invalid mnemonic while creating keyfile".into(),
            ))
        }
    }

    pub fn to_json(&self) -> Result<serde_json::Value, KeystoreError> {
        Ok(json!(self))
    }
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
