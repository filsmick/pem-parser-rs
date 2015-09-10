extern crate pem_parser;
extern crate openssl;

use std::io::prelude::*;
use std::fs::{File};
use std::path::{Path};
use std::process::Command;

use self::openssl::crypto::pkey::{PKey, EncryptionPadding};

const PLAINTEXT_FILE_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/original_data");
const PUBLIC_KEY_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/public_key");
const PRIVATE_KEY_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/private_key");
const RUST_ENCRYPTED_FILE_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/rust_encrypted_data");
const OPENSSL_CLI_ENCRYPTED_FILE_PATH: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/openssl_cli_encrypted_data");

fn read_binary_data<P: AsRef<Path>>(path: P) -> Vec<u8> {
  let mut buffer = Vec::new();
  File::open(path.as_ref()).and_then(|mut f| f.read_to_end(&mut buffer)).unwrap_or_else(|e| panic!("{}: {:?}", e, path.as_ref()));
  buffer
}

fn read_string<P: AsRef<Path>>(path: P) -> String {
  let mut string = String::new();
  File::open(path.as_ref()).and_then(|mut f| f.read_to_string(&mut string)).unwrap();
  string
}


fn openssl_cli_encrypt(plaintext_file_path: &str, encrypted_file_path: &str, private_key_path: &str) {
  let _ = Command::new("openssl")
                   .arg("rsautl")
                   .arg("-encrypt")
                   .arg("-in")
                   .arg(plaintext_file_path)
                   .arg("-out")
                   .arg(encrypted_file_path)
                   .arg("-inkey")
                   .arg(private_key_path)
                   .output()
                   .unwrap();
}

fn openssl_cli_decrypt(encrypted_file_path: &str, private_key_path: &str) -> Vec<u8> {
  let output = Command::new("openssl")
                 .arg("rsautl")
                 .arg("-decrypt")
                 .arg("-in")
                 .arg(encrypted_file_path)
                 .arg("-inkey")
                 .arg(private_key_path)
                 .output()
                 .unwrap();

  output.stdout
}


#[test]
/// Assert data encrypted with the openssl CLI and decrypted from Rust stays the same.
fn test_private_key() {
  openssl_cli_encrypt(PLAINTEXT_FILE_PATH, OPENSSL_CLI_ENCRYPTED_FILE_PATH, PRIVATE_KEY_PATH);

  let encrypted_data: Vec<u8> = read_binary_data(OPENSSL_CLI_ENCRYPTED_FILE_PATH);
  let pem_file_contents = read_string(PRIVATE_KEY_PATH);
  let der_private_key = pem_parser::pem_to_der(&pem_file_contents);

  let mut pkey = PKey::new();
  pkey.load_priv(&der_private_key);

  let decrypted_data: Vec<u8> = pkey.decrypt_with_padding(
    &encrypted_data,
    EncryptionPadding::PKCS1v15 // PKCS is the default padding scheme.
  );

  let decrypted_data: String = String::from_utf8(decrypted_data).unwrap();

  let original_data = read_string(PLAINTEXT_FILE_PATH);
  assert_eq!(decrypted_data, original_data);
}


#[test]
/// Assert data encrypted from Rust and decrypted with the openssl CLI stays the same.
fn test_public_key() {
  let public_key_pem_file_contents = read_string(PUBLIC_KEY_PATH);
  let der_public_key = pem_parser::pem_to_der(&public_key_pem_file_contents);

  let mut pkey = PKey::new();
  pkey.load_pub(&der_public_key);

  let original_data = read_binary_data(PLAINTEXT_FILE_PATH);

  let encrypted_data = pkey.encrypt_with_padding(
    &original_data,
    EncryptionPadding::PKCS1v15
  );

  let mut f = File::create(RUST_ENCRYPTED_FILE_PATH).unwrap();
  f.write_all(&encrypted_data).unwrap();

  let decrypted_data = openssl_cli_decrypt(RUST_ENCRYPTED_FILE_PATH, PRIVATE_KEY_PATH);

  assert_eq!(decrypted_data, original_data);
}
