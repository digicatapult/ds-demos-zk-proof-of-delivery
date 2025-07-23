use base64::prelude::*;
use risc0_zkvm::sha::rust_crypto::Sha256;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use std::{fs::File, io::Read};

#[derive(Serialize)]
struct FingerprintableJwk {
    e: String,
    kty: String,
    n: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        panic!("Usage: get_fingerprint /path/to/key.jwk");
    }

    let mut f = File::open(&args[1]).expect("Could not find public key file");
    let mut pk = String::new();
    f.read_to_string(&mut pk)
        .expect("Could not parse public key from file");

    let public_key: Value = serde_json::from_str(&pk).expect("Could not parse key");

    let e = public_key
        .get("e")
        .expect("Could not find mandatory field 'e'")
        .to_string()
        .replace("\"", "");

    let kty = public_key
        .get("kty")
        .expect("Could not find mandatory field 'kty'")
        .to_string()
        .replace("\"", "");

    let n = public_key
        .get("n")
        .expect("Could not find mandatory field 'n'")
        .to_string()
        .replace("\"", "");

    let fingerprintable_jwk = FingerprintableJwk { e, kty, n };
    let to_hash = serde_json::to_string(&fingerprintable_jwk).unwrap();

    let digest = Sha256::digest(to_hash);
    let fingerprint = BASE64_URL_SAFE.encode(digest).replace("=", "");
    println!("{fingerprint}");
}
