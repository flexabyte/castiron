# Cast Iron
## An ECDSA secure API signing library to accomodate secure communication with an Iron server.

This crate was inspired by the [`sec256k1`](https://crates.io/crates/secp256k1) crate that is used to perform **Elliptic Curve** signing in the Bitcoin project. Other inspirations include the [`iron-hmac`](https://crates.io/crates/iron-hmac) crate that implements `HMAC256` request signing for Iron servers. Sadly, `iron-hmac` is pretty outdated and unmaintained now, and the requirement of a pre-shared secret makes it slightly less secure than an Elliptic Curve algorithm.

It is common practice to protect sensitive website API functionality via authentication mechanisms. Often, the entity accessing these APIs is a piece of automated software outside of an interactive human session. While there are mechanisms like OAuth and API secrets that are used to grant API access, each have their weaknesses such as unnecessary complexity for particular use cases or the use of shared secrets which may not be acceptable to an implementer.

Digital signatures are widely used to provide authentication without the need for shared secrets. They also do not require a round-trip in order to authenticate the client. A server need only have a mapping between the key being used to sign the content and the authorized entity to verify that a message was signed by that entity. 

`cast-iron` aims to solve some of these problems for users who are looking to implement a solid `ECDSA` based digital signature middleware for their `Iron` servers. However, this project is still in its infancy, and so far only the more trivial and novel implementations exist. For example, to use the signature middleware:

```
use castiron::middleware::RequestSigningMiddleware;

fn hello_world(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((iron::status::Ok, "Hello World")))
}

fn main () {
    let mut chain = Chain::new(hello_world);
    chain.link_before(RequestSigningMiddleware);
    Iron::new(chain).http(format!("{}:{}", host, port))
        .expect("Unable to start server.")
}
```

The `RequestSigningMiddleware` allows the server to verify that the sender is who they say they are through the use of a `Signature` and `X-Public-Key` header like so:

```
use castiron::crypto::ecdsa;
// ...
let (pubkey, seckey) = ecdsa::generate_keys().expect("Error generating keys.");
let query = r#"{ "message": "hello" }"#;
let message = ecdsa::generate_message(query).unwrap();
let signature_der = ecdsa::sign_message(&message, &seckey);
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
```

Although the server cannot ensure the public key is coming from the user who requested it, provided the server uses `ecdsa::generate_keys()` to provide the user with their private and public keys, it can ensure that the message being sent from the client has been signed by that private key - thus ensuring that the request has not been forged or intercepted.

## Usage

This crate has not been published to crates.io yet as it's still under active development and is likely to have breaking changes in the near future. However, you can try it out like so in your Cargo.toml:

```
[dependencies]
castiron = { git = "https://github.com/flexabyte/castiron" }
```

## Development

Currently, it uses the nightly build of rust, and I like to ensure proper test coverage through the use of `grcov`:

```
grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
```

Please check the [`grcov`](https://github.com/mozilla/grcov) repository for more details on getting started if you're not familiar.


## Contributing

Developing on Cast Iron is highly welcome, feel free to submit any issues or pull requests through git, and remember - I won't accept a PR without sufficient unit/integration tests! `cargo test` is required!

## TODO

[ ] - Write a Todo list...
