use secp256k1::{Secp256k1, Message, SecretKey, PublicKey, Signature};
use base64::decode as b64_decode;
use crate::crypto::error::EcdsaError;
use sha2::{Sha256, Digest};
use rand::Rng;

pub fn generate_keys() -> Result<(PublicKey, SecretKey), EcdsaError> {
    let secp = Secp256k1::new();
    let mut key_slice = [0u8; 32];
    rand::thread_rng().fill(&mut key_slice[..]);
    let secret_key = SecretKey::from_slice(&key_slice)?;

    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok((public_key, secret_key))
}

pub fn generate_message(in_str: &str) -> Result<Message, EcdsaError> {
    let mut hasher = Sha256::new();
    hasher.input(&in_str.as_bytes());
    Ok(Message::from_slice(&hasher.result())?)
}

pub fn import_signature(in_str: &str) -> Result<Signature, EcdsaError> {
    let signature_der = b64_decode(&in_str)?;
    Ok(Signature::from_der(&signature_der)?)
}

pub fn sign_message(message: &Message, secret_key: &SecretKey) -> Vec<u8> {
    let secp = Secp256k1::new();
    secp.sign(&message, &secret_key).serialize_der().to_vec()
}

pub fn verify_signature(message: &Message, sig: &Signature, public_key: &PublicKey) -> bool {
    let secp = Secp256k1::new();
    secp.verify(message, sig, public_key).is_ok()
}

pub fn import_public_key(key_str: &str) -> Result<PublicKey, EcdsaError> {
    let bytes = hex::decode(key_str)?;
    Ok(PublicKey::from_slice(&bytes)?)
}
