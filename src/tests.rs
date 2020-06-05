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

    fn url(&self) -> String {
        format!("http://{}:{}", self.0.socket.ip(), self.0.socket.port())
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
    let server = TestServer::new(1337);

    // Test request
    let (pubkey, seckey) = generate_keys();
    let query = r#"{ "message": "hello" }"#;
    let message = generate_message(query);
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

    println!("Response: {:#?}", res);
}


#[tokio::test]
async fn test_invalid_signature() {
    // Spawn server in background
    let server = TestServer::new(1338);

    // Test request
    let (pubkey, seckey) = generate_keys();
    let query = r#"{ "message": "hello" }"#;
    let message = generate_message(query);
    let signature_der = sign_message(&message, &seckey);
    let client = reqwest::Client::builder()
        .build().expect("Error building reqwest client.");

    // Send a different public key 
    let res = client.post("http://localhost:1337")
        .body(query)
        .header("Signature", b64_encode(&signature_der))
        .header("X-Public-Key", "025e2b26716d128b0316bbe3c52d494974e1a39ec9ee447d9b470581a9e95c4cae".to_string())
        .send()
        .await
        .expect("Failure to post!");

    println!("Response: {:#?}", res);
}
