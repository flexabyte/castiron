use iron::prelude::*;
use crate::middleware::RequestSigningMiddleware;
use crate::crypto::ecdsa::{generate_keys,generate_message,sign_message};
use iron::Listening;

use base64::encode as b64_encode;
use tokio;

fn hello_world(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((iron::status::Ok, "Hello World")))
}

struct TestServer(Listening);

impl TestServer {
    fn new(port: u16) -> TestServer {
        TestServer(build_server("localhost", port))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.0.close().expect("Error closing server");
    }
}

fn build_server(host: &str, port: u16) -> iron::Listening {
    let mut chain = Chain::new(hello_world);
    chain.link_before(RequestSigningMiddleware);
    Iron::new(chain).http(format!("{}:{}", host, port))
	.expect("Unable to start server.")
}

#[tokio::test]
async fn test_valid_signature() {
    // Spawn server in background
    TestServer::new(1337);

    // Test request
    let (pubkey, seckey) = generate_keys().expect("Error generating keys.");
    let query = r#"{ "message": "hello" }"#;
    let message = generate_message(query).unwrap();
    let signature_der = sign_message(&message, &seckey);
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");
    
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("Signature", b64_encode(&signature_der))
        .header("X-Public-Key", pubkey.to_string())
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(200).unwrap())
}


#[tokio::test]
async fn test_incorrect_signature() {
    // Spawn server in background
    TestServer::new(1338);

    // Test request
    let (_, seckey) = generate_keys().expect("Error generating keys.");
    let query = r#"{ "message": "hello" }"#;
    let message = generate_message(query).unwrap();
    let signature_der = sign_message(&message, &seckey);
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1338")
        .body(query)
        .header("Signature", b64_encode(&signature_der))
        .header("X-Public-Key", "025e2b26716d128b0316bbe3c52d494974e1a39ec9ee447d9b470581a9e95c4cae".to_string())
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(401).unwrap())
}


#[tokio::test]
async fn test_missing_public_key() {
    // Spawn server in background
    TestServer::new(1339);

    // Test request
    let (_, seckey) = generate_keys().expect("Error generating keys.");
    let query = r#"{ "message": "hello" }"#;
    let message = generate_message(query).unwrap();
    let signature_der = sign_message(&message, &seckey);
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("Signature", b64_encode(&signature_der))
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(401).unwrap())
}


#[tokio::test]
async fn test_missing_signature() {
    // Spawn server in background
    TestServer::new(1340);

    // Test request
    let query = r#"{ "message": "hello" }"#;
    let (pubkey, _) = generate_keys().expect("Error generating keys.");
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("X-Public-Key", pubkey.to_string())
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(401).unwrap())
}


#[tokio::test]
async fn test_invalid_signature() {
    // Spawn server in background
    TestServer::new(1341);

    // Test request
    let query = r#"{ "message": "hello" }"#;
    let (pubkey, _) = generate_keys().expect("Error generating keys.");
    // This is not a valid DER signature (it's not actually even a signature...)
    let signature_der = "1d6cae63108637e9984d983ebbcab211072f58721c2f2a712886d066dfb27736";
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("X-Public-Key", pubkey.to_string())
        .header("Signature", b64_encode(&signature_der))
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(400).unwrap())
}


#[tokio::test]
async fn test_invalid_public_key() {
    // Spawn server in background
    TestServer::new(1342);

    // Test request
    let query = r#"{ "message": "hello" }"#;
    // This is not a valid DER signature (it's not actually even a signature...)
    let pubkey = "1d6cae63108637e9984d983ebbcab211072f58721c2f2a712886d066dfb27736";
    let signature_der = "a4244aa43ddd6e3ef9e64bb80f4ee952f68232aa008d3da9c78e3b627e5675c8";
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("X-Public-Key", pubkey.to_string())
        .header("Signature", b64_encode(&signature_der))
        .send()
        .await
        .expect("Failure to post!");

    assert_eq!(res.status(), http::StatusCode::from_u16(400).unwrap())
}

