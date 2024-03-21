use sodiumoxide::crypto::{pwhash::argon2i13, secretbox};

#[derive(Debug)]
pub enum EncryptionType {
    Unencrypted,
    Legacy,
    Ansible,
    Nacl,
}

pub fn encrypt(data: &str, encryption_type: EncryptionType) -> String {
    "".to_string()
}

pub fn encrypt_nacl(data: &str, password: &str) -> String {
    sodiumoxide::init().unwrap();
    let NACL_SALT = [
        0x13, 0x71, 0x83, 0xdf, 0xf1, 0x5a, 0x09, 0xbc, 0x9c, 0x90, 0xb5, 0x51, 0x87, 0x39, 0xe9,
        0xb1,
    ];
    let salt = argon2i13::Salt::from_slice(&NACL_SALT)
        .ok_or("Failed to create salt from slice")
        .unwrap();

    let mut password_bytes = password.as_bytes();

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
        139, 30, 112, 189, 93, 199, 196, 156, 252, 64, 20, 97, 225, 132, 77, 52, 125, 179, 224, 39,
        35, 194, 154, 228,
    ]);

    let encrypted_data = secretbox::seal(&mut data.as_bytes(), &nonce, &key);

    let mut output = Vec::new();
    output.extend_from_slice(&nonce.0);
    output.extend_from_slice(&encrypted_data);

    // Convert the encrypted data to a hexadecimal string
    let formatted_output = output
        .iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<String>();

    // Mimic Python's byte string literal format
    format!("b'{}'", formatted_output)
}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto::secretbox;

    use super::*;

    #[test]
    fn it_encrypts_nacl_correctly() {
        let cipher = "test";
        let password = "password";

        let output = encrypt_nacl(cipher, password);

        println!("'{}'", output);
    }
}
