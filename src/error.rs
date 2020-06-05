use std::fmt;
use std::io;
use iron::{IronError, status};
use std::str::Utf8Error;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    InvalidSignature,
    MissingSignatureHeader,
    MissingPublicKeyHeader,
    Utf8Error(Utf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MissingSignatureHeader => write!(f, "Missing Signature Header"),
            Error::MissingPublicKeyHeader => write!(f, "Missing X-Public-Key Header"),
            Error::InvalidSignature => write!(f, "Provided Signature is invalid"),
            Error::IoError(ref err) => write!(f, "IoError({})", err),
            Error::Utf8Error(ref err) => write!(f, "Utf8Error({})", err),
        }
    }
}

impl std::error::Error for Error {
//    fn description(&self) -> &str {
//        match *self {
//            Error::MissingSignatureHeader => "Missing Signature Header",
//            Error::MissingPublicKeyHeader => "Missing X-Public-Key Header",
//            Error::InvalidSignature => "Provided Signature is invalid",
//            Error::IoError(ref err) => &err.to_string(),
//            Error::Utf8Error(ref err) => &err.to_string(),
//        }
//    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::IoError(ref err) => Some(err),
            Error::Utf8Error(ref err) => Some(err),
            _ => None
        }
    }
}

impl From<Error> for IronError {
    fn from(err: Error) -> IronError {
        match err {
            Error::MissingSignatureHeader => IronError::new(err, status::BadRequest),
            Error::MissingPublicKeyHeader => IronError::new(err, status::BadRequest),
            Error::InvalidSignature => IronError::new(err, status::Unauthorized),
            _ => IronError::new(err, status::InternalServerError)
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

