use crate::crypto::ecdsa::generate_keys;
use crate::crypto::ecdsa::generate_message;
use crate::crypto::ecdsa::import_public_key;
use crate::crypto::ecdsa::sign_message;
use crate::crypto::ecdsa::verify_signature;
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey, Signature};

#[test]
fn test_valid_key_message_signing() {
    // generate keys
    let (public_key, secret_key) = generate_keys().unwrap();

    // convert string to message
    let message = generate_message("something I want signed.").unwrap();

    // client signs the message with their secret key
    let signature_der = sign_message(&message, &secret_key);

    // server verifies the message with their public key
    let signature =
        Signature::from_der(&signature_der).expect("Unable to deserialize DER format signature.");
    assert!(verify_signature(&message, &signature, &public_key));
}

#[test]
fn test_invalid_key_message_signing() {
    // generate keys for verification
    let (public_key, _) = generate_keys().unwrap();

    // attacker guesses the private key
    let mut key_slice = [0u8; 32];
    rand::thread_rng().fill(&mut key_slice[..]);
    let secret_key = SecretKey::from_slice(&key_slice).expect("32 bytes, within curve order");

    // convert to message
    let message = generate_message("something I want signed.").unwrap();

    // attacker signs message with their guessed private key
    let secp = Secp256k1::new();
    let sig = secp.sign(&message, &secret_key);

    // server fails to verify the message with their public key
    assert!(!verify_signature(&message, &sig, &public_key));
}

#[test]
fn test_import_publickey() {
    // Dummy public key
    let pubkey_str = "025e2b26716d128b0316bbe3c52d494974e1a39ec9ee447d9b470581a9e95c4cae";
    let public_key = import_public_key(&pubkey_str).unwrap();
    assert_eq!(public_key.to_string(), pubkey_str.to_string());
}
