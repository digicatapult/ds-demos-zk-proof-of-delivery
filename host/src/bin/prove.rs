// This file has been modified from
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs
// which has the following licence

// Copyright 2026 RISC Zero, Inc.
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

use borsh::ser::BorshSerialize;
use host::prove_token_validation;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        panic!("Usage: prove /path/to/token.jwt /path/to/receipt.bin /path/to/public_key_1.json ... /path/to/public_key_n.json");
    }

    let mut f = File::open(&args[1]).expect("Could not find token file");
    let mut token = String::new();
    f.read_to_string(&mut token)
        .expect("Could not parse token from file");

    let mut pks: Vec<String> = Vec::new();

    for i in 3..args.len() {
        let mut f = File::open(&args[i]).expect("Could not find public key file");
        let mut pk = String::new();
        f.read_to_string(&mut pk)
            .expect("Could not parse public key from file");
        pks.push(pk);
    }

    let (receipt, _journal) = prove_token_validation(token, &pks);

    let mut f = std::fs::File::create(&args[2]).expect("Could not create receipt file");
    let mut serialized_receipt = Vec::new();
    receipt
        .serialize(&mut serialized_receipt)
        .expect("Could not serialise the receipt");
    f.write_all(&serialized_receipt)
        .expect("Could not write receipt to file");
}
