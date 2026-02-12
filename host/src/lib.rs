// This file has been modified from
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/lib.rs
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

use base64::prelude::*;
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ELF;
use risc0_zkvm::sha::rust_crypto::Sha256;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;

#[derive(Serialize)]
struct FingerprintableJwk {
    e: String,
    kty: String,
    n: String,
}

pub fn compute_fingerprint(pk: String) -> String {
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

    let fingerprintable_jwk_as_str = serde_json::to_string(&fingerprintable_jwk).unwrap();

    let digest = Sha256::digest(fingerprintable_jwk_as_str);

    BASE64_URL_SAFE.encode(digest).replace("=", "")
}

pub fn prove_token_validation(token: String, pks: &Vec<String>) -> (Receipt, String) {
    // Write the JWT
    let mut binding = ExecutorEnv::builder();
    let env = binding.write(&token).expect("failed to write JWT to env");

    // Write the number of public keys
    env.write(&pks.len())
        .expect("Could not write number of public keys to env");

    // Write the public keys
    for pk in pks.iter() {
        env.write(pk).expect("failed to write pk to env");
    }
    let env = env.build().expect("failed to build env");

    let prover = default_prover();

    let receipt = prover
        .prove(env, VERIFY_TOKEN_WITH_SOME_KEY_ELF)
        .expect("failed to prove")
        .receipt;

    /*let output: String = receipt
    .journal
    .decode()
    .expect("Journal should decode to string.");*/
    let output = "".to_string();

    (receipt, output)
}

#[cfg(test)]
mod test {
    use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;

    use super::*;

    const PK: &str = r#"{
    "alg": "RS256",
    "e": "AQAB",
    "key_ops": [
        "verify"
    ],
    "kty": "RSA",
    "n": "zcQwXx3EevOSkfH0VSWqtfmWTL4c2oIzW6u83qKO1W7XjLgTqpryL5vNCaxbVTkpU-GZctit0n6kj570tfny_sy6pb2q9wlvFBmDVyD-nL5oNjP5s3qEfvy15Bl9vMGFf3zycqMaVg_7VRVwK5d8QzpnVC0AGT10QdHnyGCadfPJqazTuVRp1f3ecK7bg7596sgVb8d9Wpaz2XPykQPfphsEb40vcp1tPN95-eRCgA24PwfUaKYHQQFMEQY_atJWbffyJ91zsBRy8fEQdfuQVZIRVQgO7FTsmLmQAHxR1dl2jP8B6zonWmtqWoMHoZfa-kmTPB4wNHa8EaLvtQ1060qYFmQWWumfNFnG7HNq2gTHt1cN1HCwstRGIaU_ZHubM_FKH_gLfJPKNW0KWML9mQQzf4AVov0Yfvk89WxY8ilSRx6KodJuIKKqwVh_58PJPLmBqszEfkTjtyxPwP8X8xRXfSz-vTU6vESCk3O6TRknoJkC2BJZ_ONQ0U5dxLcx",
    "use": "sig",
    "kid": "6ab0e8e4bc121fc287e35d3e5e0efb8a"
}"#;

    const COFFEE_COMPANY_PK: &str = r#"{
    "alg": "RS256",
    "e": "AQAB",
    "key_ops": [
        "verify"
    ],
    "kty": "RSA",
    "n": "zcQwXx3EevOSkfH0VSWqtfmWTL4c2oIzW6u83qKO1W7XjLgTqpryL5vNCaxbVTkpU-GZctit0n6kj570tfny_sy6pb2q9wlvFBmDVyD-nL5oNjP5s3qEfvy15Bl9vMGFf3zycqMaVg_7VRVwK5d8QzpnVC0AGT10QdHnyGCadfPJqazTuVRp1f3ecK7bg7596sgVb8d9Wpaz2XPykQPfphsEb40vcp1tPN95-eRCgA24PwfUaKYHQQFMEQY_atJWbffyJ91zsBRy8fEQdfuQVZIRVQgO7FTsmLmQAHxR1dl2jP8B6zonWmtqWoMHoZfa-kmTPB4wNHa8EaLvtQ1060qYFmQWWumfNFnG7HNq2gTHt1cN1HCwstRGIaU_ZHubM_FKH_gLfJPKNW0KWML9mQQzf4AVov0Yfvk89WxY8ilSRx6KodJuIKKqwVh_58PJPLmBqszEfkTjtyxPwP8X8xRXfSz-vTU6vESCk3O6TRknoJkC2BJZ_ONQ0U5dxLcx",
    "use": "sig",
    "kid": "6ab0e8e4bc121fc287e35d3e5e0efb8a"
}"#;

    const OTHER_PK_1: &str = r#"{
    "alg": "RS256",
    "e": "AQAB",
    "key_ops": [
        "verify"
    ],
    "kty": "RSA",
    "n": "zcQwXx3EevOSkfH0VSWqtfmWTL4c2oIzW6u83qKO1W7XjLgTqpryL5vNCaxbVTkpU-GZctit0n6kj570tfny_sy6pb2q9wlvFBmDVyD-nL5oNjP5s3qEfvy15Bl9vMGFf3zycqMaVg_7VRVwK5d8QzpnVC0AGT10QdHnyGCadfPJqazTuVRp1f3ecK7bg7596sgVb8d9Wpaz2XPykQPfphsEb40vcp1tPN95-eRCgA24PwfUaKYHQQFMEQY_atJWbffyJ91zsBRy8fEQdfuQVZIRVQgO7FTsmLmQAHxR1dl2jP8B6zonWmtqWoMHoZfa-kmTPB4wNHa8EaLvtQ1060qYFmQWWumfNFnG7HNq2gTHt1cN1HCwstRGIaU_ZHubM_FKH_gLfJPKNW0KWML9mQQzf4AVov0Yfvk89WxY8ilSRx6KodJuIKKqwVh_58PJPLmBqszEfkTjtyxPwP8X8xRXfSz-vTU6vESCk3O6TRknoJkC2BJZ_ONQ0U5dxLcx",
    "use": "sig",
    "kid": "6ab0e8e4bc121fc287e35d3e5e0efb8a"
}"#;

    const OTHER_PK_2: &str = r#"{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "alg": "RS256",
    "n": "tRHS91Q-CuiEbHtrC93c_2eJiigdz1cIhavaUhmNZiTNZLnSHvbuzZHla0x2lYk7AcgM5N20JOL_Kq_9gjMVE18DGnQ3QijKsc389hB-XSdEw0mHpQ_K59LpCUOsB72WaaBXWcURAYGVkUxkJfVek6bo9S3T8EEyJLTx5C5oN5FQ9Gk_zuevg7k8m4Xaq1P7eZJJ4ylgfU3vzK6BOeDuEvhmd9MtQYJwD-pkpBt80CttdqwKM5itOS23brLBwFJkUNtLb-MqxN-q8P3HkS00dNEOQEJ3aBkv9AJKKKborEQfiAXNAUls82_rg038AhIzPaSDjHHOiov_mxnpKsZ_oQ"
}"#;

    #[test]
    pub fn test_compute_fingerprint() {
        assert_eq!(
            compute_fingerprint(PK.to_string()),
            "US_g-NguIHYSNN95ZHMM0_gUI4iM9afv8KPyySaAnUQ".to_string()
        );
    }

    #[test]
    pub fn test_prove_token_validation_fails_no_pk() {
        let token: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InJlZmVyZW5jZSIsInZhbHVlIjoiNDYxMzYzMjMtNDc3My00OTYwLWE0YTItYTkwNDVkOGIxNjBkIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoiaXNzdWVyX2lkIiwidmFsdWUiOiJDb2ZmZWUgQ2hhaW4gMiIsImlzX3ByaXZhdGUiOnRydWV9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQ29mZmVlIFN1cHBsaWVyIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoicHJvZHVjdCIsInZhbHVlIjoicmF3IGNvZmZlZSBiZWFucyIsImlzX3ByaXZhdGUiOmZhbHNlfSx7ImtleSI6InF1YW50aXR5IiwidmFsdWUiOiIxMDAwIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoiY29zdCIsInZhbHVlIjoiNDAwMCIsImlzX3ByaXZhdGUiOnRydWV9XX0.FYOBvZ1VynCITa4noP8tYEP1dPa3L5XTT6Toxa1nAxU1dGq_VeJ9nW3yk0Ypa69I5KmijrcscVJdqIpbE4DHK5zEzyuT4BxYxZbxijiaKfXkH4kPaCr2iQD3FZX7TQs_HzKtELR8nW1gXegqh_RTudmjZgMH1CK3ic2OzbRsWnRP9oXInStZ6q3EsI1GQvxyXbfKaj5SRtmyfFXIIkQVwWM_cVsAwkkeu-s9r4A_MsEMbUJ210-0_NGxWaqcW2lIPjgLZHoYMdohjM94zkjusgrZas2jhEtif3LwZOgmU8oYldtG-5pMji1bWbiBI0pEx43G5gUm2B-yf9TAP3rbCNkJwo9E_5MeNV5TkWDTPlgHh4fw5-u5Wfk5p9VMRNC3tpmOVvk-PaLQyPmsu8ynYptz8nXNA6HdwLyh5bMGFJgnepxll-iWtn0iWWj-In1_Ht6AUuj9DzGYL-zXfJGykkjyHrus8OE5nREyfCZFKQ-z-ejZRSpufQ2Z14Sdheuc".to_string();
        let pks: Vec<String> = [OTHER_PK_1.to_string(), OTHER_PK_2.to_string()].to_vec();

        let (receipt, _) = prove_token_validation(token, &pks);
        assert!(receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID).is_ok());
    }

    #[test]
    #[should_panic]
    pub fn test_prove_token_validation_fails_bad_sig() {
        let token: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InJlZmVyZW5jZSIsInZhbHVlIjoiNDYxMzYzMjMtNDc3My00OTYwLWE0YTItYTkwNDVkOGIxNjBkIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoiaXNzdWVyX2lkIiwidmFsdWUiOiJDb2ZmZWUgQ2hhaW4gMiIsImlzX3ByaXZhdGUiOnRydWV9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQ29mZmVlIFN1cHBsaWVyIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoicHJvZHVjdCIsInZhbHVlIjoicmF3IGNvZmZlZSBiZWFucyIsImlzX3ByaXZhdGUiOmZhbHNlfSx7ImtleSI6InF1YW50aXR5IiwidmFsdWUiOiIxMDAwIiwiaXNfcHJpdmF0ZSI6ZmFsc2V9LHsia2V5IjoiY29zdCIsInZhbHVlIjoiNDAwMCIsImlzX3ByaXZhdGUiOnRydWV9XX0.FYOBvZ1VynCITa4noP8tYEP1dPa3L5XTT6Toxa1nAxU1dGq_VeJ9nW3yk0Ypa69I5KmijrcscVJdqIpbE4DHK5zEzyuT4BxYxZbxijiaKfXkH4kPaCr2iQD3FZX7TQs_HzKtELR8nW1gXegqh_RTudmjZgMH1CK3ic2OzbRsWnRP9oXInStZ6q3EsI1GQvxyXbfKaj5SRtmyfFXIIkQVwWM_cVsAwkkeu-s9r4A_MsEMbUJ210-0_NGxWaqcW2lIPjgLZHoYMdohjM94zkjusgrZas2jhEtif3LwZOgmU8oYldtG-5pMji1bWbiBI0pEx43G5gUm2B-yf9TAP3rbCNkJwo9E_5MeNV5TkWDUPlgHh4fw5-u5Wfk5p9VMRNC3tpmOVvk-PaLQyPmsu8ynYptz8nXNA6HdwLyh5bMGFJgnepxll-iWtn0iWWj-In1_Ht6AUuj9DzGYL-zXfJGykkjyHrus8OE5nREyfCZFKQ-z-ejZRSpufQ2Z14Sdheuc".to_string();
        let pks: Vec<String> = [COFFEE_COMPANY_PK.to_string(), OTHER_PK_1.to_string()].to_vec();

        let (receipt, _) = prove_token_validation(token, &pks);
        assert!(receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID).is_ok());
    }
}
