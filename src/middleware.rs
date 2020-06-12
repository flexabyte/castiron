use iron::prelude::*;
use iron::{BeforeMiddleware};
use crate::crypto::ecdsa;
use std::io::Read;
use crate::error::Error;

pub struct RequestSigningMiddleware;

impl BeforeMiddleware for RequestSigningMiddleware {
    fn before(&self, request: &mut Request) -> IronResult<()> {
        let mut query = "".to_string();
        let result = request.body.read_to_string(&mut query);
        if result.is_err() {
            let err = Error::IoError(result.err().unwrap());
            return Err(iron::IronError::new(err, iron::status::InternalServerError));
        }

        // Check and unwrap headers 
        let signature_header = request.headers.get_raw("Signature")
              .and_then(|vals| std::str::from_utf8 (&vals[0]).ok());
        if signature_header.is_none() {
            // InvalidSignature
            let err = Error::MissingSignatureHeader;
            return Err(iron::IronError::new(err, iron::status::BadRequest));
        }
        let public_key_header = request.headers.get_raw("X-Public-Key")
              .and_then(|vals| std::str::from_utf8 (&vals[0]).ok());
        if public_key_header.is_none() {
            // InvalidSignature
            let err = Error::MissingPublicKeyHeader;
            return Err(iron::IronError::new(err, iron::status::BadRequest));
        }
        
        // Convert to an ECDSA 32 byte message
        let message = ecdsa::generate_message(&query);

        // I don't think this can fail... but just in case
        if message.is_err() {
            let err = Error::InvalidMessage;
            return Err(iron::IronError::new(err, iron::status::BadRequest));
        }
        let signature = ecdsa::import_signature(signature_header.unwrap());
        if signature.is_err() {
            let err = Error::InvalidSignature;
            return Err(iron::IronError::new(err, iron::status::BadRequest));
        }
        let public_key = ecdsa::import_public_key(public_key_header.unwrap());
        if public_key.is_err() {
            let err = Error::InvalidPublicKey;
            return Err(iron::IronError::new(err, iron::status::BadRequest));
        }

        if !ecdsa::verify_signature(&message.unwrap(), &signature.unwrap(), &public_key.unwrap()) {
            // InvalidSignature
            let err = Error::InvalidSignature;
            return Err(iron::IronError::new(err, iron::status::Unauthorized));
        }

        // All good!
        return Ok(());
    }
}

// Now a user can chain the RequestSigningMiddleware in their request chain like so: 
// ```
// let mut chain = Chain::new(hello_handler);
// chain.link_before(RequestLoggingMiddleware {});
// ```

