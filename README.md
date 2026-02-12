# Supply Chain Proof Demo
This demo is a modified version of the risc0 example for JWT verification from
the main risc0 repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

## Scenario
A user wants to prove that they have a JWT signed by one of a number of possible
keys, but they do not want to reveal which (perhaps the customers have required
that they must not share this information).  In our example, a coffee supplier
wants to prove they are capable of supplying a large amount of coffee without
revealing the cost or the (specific) customer, and they do this by proving that
they have a signed invoice from one of several customers.

The signed JWT attests to a set of claims provided as input.

The public inputs to the proof are:
- A number of public keys, corresponding to potential customers.
- Claims stated by the JWT.  In this example, we have defined custom claims that
  record the public key associated with the supplier and the amount of product
  that they shipped.

The private inputs to the proof are:
- The JWT (which includes metadata linking the signature to the customer) 

The proof proves the statement: 'This JWT was signed by a secret key
corresponding to one of the input public  keys and records that a shipment of
size <1000> was sent'.

## Installation
- Install [rust](https://rust-lang.org/tools/install) and
[RISC0](https://dev.risczero.com/api/zkvm/install), then run `cargo build
--release --bins` in the repository root.
- Install dependencies for the frontend:
```bash
cd frontend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the demo
The process is as follows:
- Generate and sign a proof of delivery
- Generate a zero-knowledge proof of delivery
- Verify the proof

Each operation can be performed using a Python-based GUI, e.g.:
```bash
cd frontend
source .venv/bin/activate
python gen_and_sign_pod.py
```

Test data is provided in the `./test_data` directory.

## Limitations
Note that due to limitations of the GUI library, the frontend does not display
properly when using dark mode on MacOS.