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

#[derive(Debug)]
pub enum EncryptionType {
    Legacy,
    Ansible,
    Nacl,
}

use bip39::Mnemonic;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Keyfile {
    account_id: String,
    public_key: String,
    secret_phrase: Option<String>,
    secret_seed: Option<String>,
    ss58_address: String,
}

#[derive(Debug)]
pub struct KeyFile {
    pub path: String,
    pub name: String,
    pub kind: EncryptionType,
    pub key: String,
    pub password: String,
}

impl KeyFile {
    pub fn new(words: &string) -> KeyFile {
        let mnemonic = Mnemonic::generate(words)
            .map_err(|e| CommandError::Input(format!("Mnemonic generation failed: {e}").into()))?;

        let password = args.keystore_params.read_password()?;

        let phrase = mnemonic.words().collect::<Vec<_>>().join(" ");
    }
}

pub fn validate_password(password: &str) -> bool {
    let min_length = 8;

    if password.len() < min_length {
        return false;
    }

    return true;
}
