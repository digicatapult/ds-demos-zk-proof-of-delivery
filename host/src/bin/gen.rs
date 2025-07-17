// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use jwt_core::{CustomClaims, Issuer};
use std::fs::File;
use std::io::prelude::*;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();

    let claims = CustomClaims {
        supplier_did: "did:web:example.com".to_string(),
        delivery_size_per_month: "1000".to_string(),
    };

    let mut f = std::fs::File::open(&args[1])
        .expect("Please provide issuer secret key in PEM format as first argument");
    let mut secret_key = "".to_string();
    f.read_to_string(&mut secret_key).unwrap();

    let iss = secret_key
        .parse::<Issuer>()
        .expect("failed to create issuer from secret key");
    let token = iss
        .generate_token(&claims)
        .expect("failed to generate token");

    let mut f = File::create("./issued_token.jwt").expect("could not create file");
    f.write_all(&token.as_bytes())
        .expect("could not write to file");
}
