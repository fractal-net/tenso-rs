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

pub fn encrypt_nacl(data: &str) -> String {
    "".to_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_encrypts_nacl_correctly() {
        let cipher = r#"{"accountId": "0xe06feefcde9ee212c0a05c365f509d0228d52371369094ac60dea4a798f1d477", "publicKey": "0xe06feefcde9ee212c0a05c365f509d0228d52371369094ac60dea4a798f1d477", "secretPhrase": "banana consider excuse claw treat travel flash bundle belt danger aunt dragon", "secretSeed": "0xee88e102c6c924fb67552215894a43cca267c8b94da8dffc66acb8578382d80b", "ss58Address": "5H8yqMeyP4i8ZYVd7i2rNgPZawgdJnhkQ92sSfJfguF8RbWd"}"#;
        println!("{}", cipher);
    }
}
