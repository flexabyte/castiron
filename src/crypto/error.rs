use base64::DecodeError as Base64DecodeError;
use hex::FromHexError as HexDecodeError;
use secp256k1::Error as SignError;
use std::fmt;

// Generic Error types handling
#[derive(Debug)]
pub enum EcdsaError {
    Sign(SignError),
    Base64Decode(Base64DecodeError),
    HexDecode(HexDecodeError),
}

impl fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EcdsaError::Sign(ref err) => write!(f, "Unable to sign message: {}", err),
            EcdsaError::Base64Decode(ref err) => {
                write!(f, "Unable to decode base64 string: {}", err)
            }
            EcdsaError::HexDecode(ref err) => write!(f, "Unable to decode hex string: {}", err),
        }
    }
}

impl std::error::Error for EcdsaError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            EcdsaError::Base64Decode(ref err) => Some(err),
            EcdsaError::HexDecode(ref err) => Some(err),
            _ => None,
        }
    }
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
