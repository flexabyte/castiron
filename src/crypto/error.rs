use secp256k1::Error as SignError;
use base64::DecodeError as Base64DecodeError;
use hex::FromHexError as HexDecodeError;

// Generic Error types handling
#[derive(Debug)]
pub enum EcdsaError {
    Sign(SignError),
    Base64Decode(Base64DecodeError),
    HexDecode(HexDecodeError),
}

impl From<SignError> for EcdsaError {
    fn from(e: SignError) -> Self {
        EcdsaError::Sign(e)
    }
}

impl From<Base64DecodeError> for EcdsaError {
    fn from(e: Base64DecodeError) -> Self {
        EcdsaError::Base64Decode(e)
    }
}

impl From<HexDecodeError> for EcdsaError {
    fn from(e: HexDecodeError) -> Self {
        EcdsaError::HexDecode(e)
    }
}

