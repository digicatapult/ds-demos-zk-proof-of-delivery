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

use jwt_core::Validator;
use risc0_zkvm::guest::env;

fn main() {
    // read the token input
    let token: String = env::read();
    let pk_0: String = env::read();
    let pk_1: String = env::read();
    let pk_2: String = env::read();

    let validator = pk_0
        .parse::<Validator>()
        .expect("failed to create validator from key");
    let mut valid_token = validator.validate_token_integrity(&token);

    if valid_token.is_err() {
        let validator = pk_1
            .parse::<Validator>()
            .expect("failed to create validator from key");
        valid_token = validator.validate_token_integrity(&token);
    }

    if valid_token.is_err() {
        let validator = pk_2
            .parse::<Validator>()
            .expect("failed to create validator from key");
        valid_token = validator.validate_token_integrity(&token);
    }

    let valid_token =
        valid_token.unwrap_or_else(|_| panic!("failed to validate token with any key"));

    let data = [
        pk_0.to_string(),
        pk_1.to_string(),
        pk_2.to_string(),
        valid_token.claims().custom.supplier_did.clone(),
        valid_token.claims().custom.delivery_size_per_month.clone(),
    ]
    .join("||");

    env::commit(&data);
}
