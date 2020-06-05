use iron::prelude::*;
use iron::{BeforeMiddleware, AfterMiddleware, typemap};
use crate::crypto::ecdsa;
use std::collections::HashMap;
use std::io::Read;
use std::str;

pub struct RequestSigningMiddleware;

impl BeforeMiddleware for RequestSigningMiddleware {
    fn before(&self, request: &mut Request) -> IronResult<()> {
        let mut query = "".to_string();
        request.body.read_to_string(&mut query);
        println!("{}", query);
        let signature_header = request.headers.get_raw("Signature")
              .and_then(|vals| std::str::from_utf8 (&vals[0]).ok()).unwrap();
        let public_key_header = request.headers.get_raw("X-Public-Key")
              .and_then(|vals| std::str::from_utf8 (&vals[0]).ok()).unwrap();
        let message = ecdsa::generate_message(&query);
        let signature = ecdsa::import_signature(signature_header);
        let public_key = ecdsa::import_public_key(public_key_header);

        if ecdsa::verify_signature(&message, &signature, &public_key) {
            return Ok(());
        }
        // Return our own Error type here...
        Ok(())
    }
}

// Now a user can chain the RequestSigningMiddleware in their request chain like so: 
// ```
// let mut chain = Chain::new(hello_handler);
// chain.link_before(RequestLoggingMiddleware {});
// ```
