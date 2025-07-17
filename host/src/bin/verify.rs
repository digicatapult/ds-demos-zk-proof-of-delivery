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

use borsh::de::BorshDeserialize;
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;
use risc0_zkvm::Receipt;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let receipt = std::fs::read("./receipt.bin").expect("Could not read receipt from file");
    let receipt =
        Receipt::try_from_slice(&receipt).expect("Could not deserialise bytes as receipt");

    let res = receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID);
    if res.is_ok() {
        println!("Proved and succesfully verified!");
        println!("Result is: {:?}", res)
    } else {
        println!("Failed to verify proof!")
    }
}
