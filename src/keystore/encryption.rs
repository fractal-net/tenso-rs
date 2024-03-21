use sodiumoxide::crypto::{pwhash::argon2i13, secretbox};

use super::error::KeystoreError;

const NACL_SALT: [u8; 16] = [
    0x13, 0x71, 0x83, 0xdf, 0xf1, 0x5a, 0x09, 0xbc, 0x9c, 0x90, 0xb5, 0x51, 0x87, 0x39, 0xe9, 0xb1,
];

#[derive(Debug)]
pub enum EncryptionType {
    Legacy,
    Ansible,
    Nacl,
}

pub fn encrypt(
    data: &str,
    password: &str,
    encryption_type: EncryptionType,
) -> Result<String, KeystoreError> {
    match encryption_type {
        EncryptionType::Nacl => {
            let encrypted_data = encrypt_nacl(data, password);
            let formatted_output = encrypted_data
                .iter()
                .map(|&b| format!("{:02x}", b))
                .collect::<String>();

            Ok(formatted_output)
        }
        _ => Err(KeystoreError::UnsupportedEncryptionType),
    }
}

pub fn encrypt_nacl(data: &str, password: &str) -> Vec<u8> {
    // todo: find a clever place to put this
    sodiumoxide::init().unwrap();

    let salt = argon2i13::Salt::from_slice(&NACL_SALT).unwrap();

    let password_bytes = password.as_bytes();

    let mut pk = [0; secretbox::KEYBYTES];

    let key_bytes = argon2i13::derive_key(
        &mut pk,
        password_bytes,
        &salt,
        argon2i13::OPSLIMIT_SENSITIVE,
        argon2i13::MEMLIMIT_SENSITIVE,
    )
    .unwrap();

    let key = secretbox::Key::from_slice(&key_bytes).unwrap();

    let nonce = secretbox::gen_nonce();

    let encrypted_data = secretbox::seal(&mut data.as_bytes(), &nonce, &key);

    let mut output = "$NACL".as_bytes().to_vec();
    output.extend_from_slice(&nonce.0);
    output.extend_from_slice(&encrypted_data);

    output
}

pub fn decrypt_nacl() -> String {
    "".to_string()
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn it_encrypts_nacl_correctly() {
        let cipher = "test";
        let password = "password";
        let expected_output = "244e41434c8b1e70bd5dc7c49cfc401461e1844d347db3e02723c29ae428117ae4a29f30d15425c8d29712be07e313212b";

        let salt = argon2i13::Salt::from_slice(&NACL_SALT).unwrap();

        let password_bytes = password.as_bytes();

        let mut pk = [0; secretbox::KEYBYTES];

        let key_bytes = argon2i13::derive_key(
            &mut pk,
            password_bytes,
            &salt,
            argon2i13::OPSLIMIT_SENSITIVE,
            argon2i13::MEMLIMIT_SENSITIVE,
        )
        .unwrap();

        let key = secretbox::Key::from_slice(&key_bytes).unwrap();

        let nonce = secretbox::Nonce([
            139, 30, 112, 189, 93, 199, 196, 156, 252, 64, 20, 97, 225, 132, 77, 52, 125, 179, 224,
            39, 35, 194, 154, 228,
        ]);

        let encrypted_data = secretbox::seal(&mut cipher.as_bytes(), &nonce, &key);

        let mut output = "$NACL".as_bytes().to_vec();
        output.extend_from_slice(&nonce.0);
        output.extend_from_slice(&encrypted_data);

        let formatted_output = output
            .iter()
            .map(|&b| format!("{:02x}", b))
            .collect::<String>();

        assert_eq!(formatted_output, expected_output);
    }
}
