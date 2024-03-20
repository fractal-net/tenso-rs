use futures::task::waker;
use sodiumoxide::crypto::{pwhash, secretbox};

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
    const NACL_SALT: &[u8] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x87\x39\xe9\xb1";

    let mut password_bytes = password.as_bytes();

    let salt = pwhash::gen_salt();
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = k;

        let key = pwhash::derive_key(
            kb,
            password_bytes,
            &salt,
            pwhash::OPSLIMIT_SENSITIVE,
            pwhash::MEMLIMIT_SENSITIVE,
        );
    }
    let encrypted_data = secretbox::seal(data.as_bytes(), &salt, &k);

    let formatted_output = encrypted_data
        .iter()
        .map(|&b| format!("\\x{:02x}", b))
        .collect::<String>();

    formatted_output
}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto::secretbox;

    use super::*;

    #[test]
    fn it_encrypts_nacl_correctly() {
        let cipher = r#"{"accountId": "0x56c6ac6d20fd1c9e15532f17cc169de2f84868857751f5850c66f5183d673a5e", "publicKey": "0x56c6ac6d20fd1c9e15532f17cc169de2f84868857751f5850c66f5183d673a5e", "secretPhrase": "label same sand actor device admit charge venture cancel mule kitchen pink", "secretSeed": "0x9373e9cdefe431494d536061af63b44cccdba3113e9997c95f7f6a29af59a81b", "ss58Address": "5E2UzamgGp4tiDs4mGtyfo6MNRPC6hPjNyhNTGQjwBWHyru9"}"#;

        let password = "password";
        let output = encrypt_nacl(cipher, password);

        println!("'{}'", output);
        let expecte = r#"b'\'\xdc\xb7\x17\x15\xdfB,\x90\x1cU\xc9W\xe2u\x8fp\x9a\xc4\xe8E\x91\xb8\xd3\xd5!c\x92\x9bq}\x80\xe1\x1d\x0c\xe7\r\x8c~\x0f\x05ucl\xe9O\x19\x9a\x8f\x99X;\xd6\x1cH\xae!Q<\x8b\x0c\xac\xc3a\x8b8\x8d\x95~\xbf\xdfc\xe9w\x0c\xf2\xbf\xb0t\x1a\xad9f\x117 \x9fN\x9a\x8b\x87rV-\xd36d\xa3\xc9h@/\xd2\xc3Tk\xf8\xe3U\xa1"\x04c\xf1\x92k0\x12\xbd\x8f\xe6\xeb\x99\xbf@\x12\x1eL\x7f\xa3\xb3\xc6\xc7\xdb\x1b1L\xfe\xa4\x96<\xd63\xb2\x15\x07Y}\xcb^y\x16\xb7\x1aKI\xdc\'R\xd5\xee\xb3\xff\xcc\'\x1fFv}\x8b\xd1x\xea\xc6\x1e5\xb7\xa37\xfa\x1f\xb7lF\x08\xa1\xc8\xe8\x9fN<\xde\xb7Q&\x88;\x17\x13\x11\xd9\x82@\xaf|]\xab~\n\xf6Ss\x82\xa6\xea\xf5Ndd\xb8\xc7x\xed\xd7\xb5\x02h\x1bS\xce\x92\x07\xb0\xc1\x80\xe9\xc3(z\xf8\x9fd\x00\xc5\xb5\x17\xa3\xe2S\x18\x14\xe5\xd3K\x9b\xae\xfb\xe1\x0b\xc45\x92$h\x8d\x8b\xdbK\xf6\x93&\xa4\x04`[\',(P\xce\xc7\x05^\x95\xb8\xe3\xd3\x823\x89=\xf5\xba\x01\xc7\xe5j\x03m\xbc\x17*\xd7\xd6\xb5@\xealPf\xfaswV\x972\xcf\x7fT\xa4\xaf\xe2l\x1f\x96d\xbc6\x9dD\xfd\xb7\xd5|\x9f\x0b$\x93\xc1\xc5\x11\xa0\x03\x92~\xf7R\xa4\x9e>]\xb2\xdc \xb3\xcf\xb7r9\xf1c\x1c\x9c\xb5\x0f\x92\x97h\xe5\x14)\xbf1V\t\x05\xa7g\x98\xea\x85\x1f\x9e\x8fU\xbc\xb7t\x8e(\xd3\x1e\x1e\x83\xa5m\x937W\x99\xe6\t\xb7N\x1fm2EE\xf1\xdaR\x87\xbd\xea\xb5\xa3^\xb6\x0c|s/\x80\x8d\x1f\xa5\xc6\xd8\x8emE\'\x9a\x1b\x1d\xdf\x0e%)\xc4\x08\xe7\xd2\xa5!\x8b\x84\xc6\xf9\xee'"#;

        // let
    }
}

// def encrypt_keyfile_data(keyfile_data: bytes, password: str = None) -> bytes:
//     """Encrypts the passed keyfile data using ansible vault.
//
//     Args:
//         keyfile_data (bytes): The bytes to encrypt.
//         password (str, optional): The password used to encrypt the data. If ``None``, asks for user input.
//     Returns:
//         encrypted_data (bytes): The encrypted data.
//     """
//     password = bittensor.ask_password_to_encrypt() if password is None else password
//     password = bytes(password, "utf-8")
//
//     kdf = pwhash.argon2i.kdf
//     key = kdf(
//         secret.SecretBox.KEY_SIZE,
//         password,
//         NACL_SALT,
//         opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
//         memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
//     )
//     box = secret.SecretBox(key)
//     encrypted = box.encrypt(keyfile_data)
//     return b"$NACL" + encrypted
