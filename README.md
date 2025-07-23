# Supply Chain Proof Demo

This demo is a modified version of the risc0 example for JWT verification from
the main risc0 repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

## Proof scenario
A user wants to prove that they have a JWT signed by one of a number of possible
keys, but they do not want to reveal which (perhaps the customers have required
that they must not share this information).

The signed JWT attests to a set of custom claims that can be modified as needed.
An example is given in `./host/custom_claims.json`.

The public inputs to the proof are:
- A number of public keys, corresponding to potential customers.
- Claims stated by the JWT.  In this example, we have defined custom claims that
  record the DID associated with the supplier and the amount of product that
  they shipped.

The private inputs to the proof are:
- The JWT (which includes metadata linking the signature to the consumer) 

The proof proves the statement: 'This JWT was signed by a secret key
corresponding to one of the input public  keys and records that a shipment of
size 1000 was sent'.

## Installation
Install RISC0, then run `cargo build --release --bins`

## Running the demo
Note that since proving takes considerable resources, it is recommended to use
the development flag when testing (prefix each command with `RISC0_DEV_MODE=1`).

### Generate a token
Run `./target/release/gen ./host/test_sk.json ./host/custom_claims.json
./token.jwt`.  This will generate a JWT signed using a secret provided as
command-line argument, written to the filesystem as `./issued_token.jwt`.  The
corresponding public key should be provided as input to the proving routine,
along with two other 'fake' public keys.

The JWT has custom fields that can be modified in `./core/src/lib.rs` if
desirable (with necessary changes propagated throughout the repository).

### Prove the statement
Run `./target/release/prove ./token.jwt ./receipt.bin ./host/test_pk.json` to
create the proof. Any number of trailing public keys can be provided and each
will be used to attempt verification in turn until one succeeds.  This will
likely take a long time and use lots of RAM/swap if the development flag is not
used.

This process compiles a binary
`./target/riscv32im-risc0-zkvm-elf/verify_token_with_some_key.bin` of RISC-V-ish
bytecode.  This binary is the compilation of the code in `./methods/guest`.  The
ZKVM then proves its honest execution.

In other words, the proof proves that the code in `./methods/guest/src` is
honestly executed.  It should therefore not contain secret data compiled into
it, since this is the 'circuit' the verifier will see when proving; secret data
should be passed in from the host, along with any other per-proof
parameters (such as the public keys).

The journal is the public data associated with the proof and is included in the
receipt.  The act of committing to the journal is itself a process undertaken in
the code that is proven honestly executed, which allows the prover to attest to
the fact that specific inputs were used in the proof rather than dummy ones (in
our example, the public keys provided as input).

### Verify the proof
Run `./target/release/verify ./receipt.bin` to verify the proof. 