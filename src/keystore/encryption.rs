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
) -> Result<Vec<u8>, KeystoreError> {
    match encryption_type {
        EncryptionType::Nacl => {
            let encrypted_data = encrypt_nacl(data, password);
            Ok(encrypted_data)
        }
        _ => Err(KeystoreError::UnsupportedEncryptionType),
    }
}

pub fn decrypt(
    data: &Vec<u8>,
    password: &str,
    encryption_type: EncryptionType,
) -> Result<Vec<u8>, KeystoreError> {
    match encryption_type {
        EncryptionType::Nacl => {
            let decrypted_data = decrypt_nacl(data, password);
            Ok(decrypted_data)
        }
        _ => Err(KeystoreError::UnsupportedEncryptionType),
    }
}

fn get_nacl_key(password: &str) -> secretbox::Key {
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

    secretbox::Key::from_slice(&key_bytes).unwrap()
}

fn encrypt_nacl(data: &str, password: &str) -> Vec<u8> {
    // todo: find a clever place to put this
    sodiumoxide::init().unwrap();

    let key = get_nacl_key(password);

    let nonce = secretbox::gen_nonce();

    let encrypted_data = secretbox::seal(&mut data.as_bytes(), &nonce, &key);

    let mut output = "$NACL".as_bytes().to_vec();
    output.extend_from_slice(&nonce.0);
    output.extend_from_slice(&encrypted_data);

    output
}

fn extract_nonce_from_encryption_type(
    encryption_type: EncryptionType,
    data: &Vec<u8>,
) -> secretbox::Nonce {
    match encryption_type {
        EncryptionType::Nacl => extract_nonce_nacl(data), // Skip the "$NACL" prefix
        _ => panic!("Unsupported encryption type"),
    }
}

fn extract_nonce_nacl(data: &Vec<u8>) -> secretbox::Nonce {
    let nonce_start = 5; // Skip the "$NACL" prefix
    let nonce_end = nonce_start + secretbox::NONCEBYTES; // secretbox::NONCEBYTES should be 24
    let nonce_slice = &data[nonce_start..nonce_end];
    let nonce_array: [u8; 24] = nonce_slice.try_into().expect("Slice with incorrect length"); // Convert the slice into an array
    secretbox::Nonce(nonce_array)
}

fn extract_encrypted_data_nacl(data: &Vec<u8>) -> Vec<u8> {
    let nonce_end = 5 + secretbox::NONCEBYTES; // secretbox::NONCEBYTES should be 24
    data[nonce_end..].to_vec()
}

pub fn decrypt_nacl(data: &Vec<u8>, password: &str) -> Vec<u8> {
    // todo: find a clever place to put this
    sodiumoxide::init().unwrap();
    let key = get_nacl_key(password);
    let nonce = extract_nonce_from_encryption_type(EncryptionType::Nacl, data);
    let encrypted_data = extract_encrypted_data_nacl(data);

    let decrypted = secretbox::open(&encrypted_data, &nonce, &key).unwrap();

    decrypted
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

    #[test]
    fn it_fetches_nonce_correctly() {
        let expected_nonce = secretbox::Nonce([
            139, 30, 112, 189, 93, 199, 196, 156, 252, 64, 20, 97, 225, 132, 77, 52, 125, 179, 224,
            39, 35, 194, 154, 228,
        ]);

        let cipher = "244e41434c8b1e70bd5dc7c49cfc401461e1844d347db3e02723c29ae428117ae4a29f30d15425c8d29712be07e313212b";
        let cipher_bytes = hex::decode(&cipher).unwrap();

        let actual_nonce = extract_nonce_nacl(&cipher_bytes);

        assert_eq!(actual_nonce, expected_nonce);
    }

    #[test]
    fn it_fetchs_encrypted_data_correctly() {
        let expected_encrypted_data = vec![
            40, 17, 122, 228, 162, 159, 48, 209, 84, 37, 200, 210, 151, 18, 190, 7, 227, 19, 33, 43,
        ];

        let cipher = "244e41434c8b1e70bd5dc7c49cfc401461e1844d347db3e02723c29ae428117ae4a29f30d15425c8d29712be07e313212b";
        let cipher_bytes = hex::decode(&cipher).unwrap();

        let actual_encrypted_data = extract_encrypted_data_nacl(&cipher_bytes);

        assert_eq!(actual_encrypted_data, expected_encrypted_data);
    }

    #[test]
    fn it_decrypts_nacl_correctly() {
        let expected_output = r#"{"accountId": "0x8675d3e27ba8a6b6a3cf23668d346ba398b8fd7b7c90f9d72789b21458cd192e", "publicKey": "0x8675d3e27ba8a6b6a3cf23668d346ba398b8fd7b7c90f9d72789b21458cd192e", "secretPhrase": "scheme coin blush private reunion door tuition grid world diagram reopen syrup", "secretSeed": "0x624517f37eabbc2c3d1f23a23de20107f57c2749264b84feac3b0eba5379301e", "ss58Address": "5F71GxBcHF9UfE6uiDcFsgbPNmHJGwPtNfg3F87HEeVczotP"}"#;

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let resource_path = std::path::Path::new(&manifest_dir).join("resources/testkey/coldkey");

        let data = std::fs::read(resource_path).unwrap();

        let password = "Password1%";
        let decrypted = decrypt_nacl(&data, password);
        let decrypted_str = std::str::from_utf8(&decrypted).unwrap();
        assert_eq!(decrypted_str, expected_output);
    }
}
