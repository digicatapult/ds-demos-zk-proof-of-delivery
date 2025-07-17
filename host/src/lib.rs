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

use methods::VERIFY_TOKEN_WITH_SOME_KEY_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove_token_validation(
    token: String,
    pk_0: &String,
    pk_1: &String,
    pk_2: &String,
) -> (Receipt, String) {
    let env = ExecutorEnv::builder()
        .write(&token)
        .expect("failed to write JWT to env")
        .write(pk_0)
        .expect("failed to write pk to env")
        .write(pk_1)
        .expect("failed to write pk to env")
        .write(pk_2)
        .expect("failed to write pk to env")
        .build()
        .expect("failed to build env");

    let prover = default_prover();

    let receipt = prover
        .prove(env, VERIFY_TOKEN_WITH_SOME_KEY_ELF)
        .expect("failed to prove")
        .receipt;

    let output: String = receipt
        .journal
        .decode()
        .expect("Journal should decode to string.");

    (receipt, output)
}
