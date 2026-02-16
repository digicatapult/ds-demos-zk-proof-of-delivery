import subprocess
import os
from gooey import Gooey, GooeyParser

TMP_DIR="./"

@Gooey(program_name="Generate a Zero Knowledge Proof of Delivery")
def main():
    parser = GooeyParser(description="")
    input_output_group = parser.add_argument_group("Input/Output files")
    input_output_group.add_argument(
        'signed_pod', help="Input Proof of Delivery file", widget="FileChooser", default=TMP_DIR + "proof_of_delivery.jwt"
    )
    input_output_group.add_argument('zk_pod', help="Output Zero-Knowledge Proof of Delivery file", widget="FileSaver", default=TMP_DIR + "zk_pod.bin")

    public_key_group = parser.add_argument_group(
        "Public keys", 
        "Choose the public keys to claim signed the Proof of Delivery"
    )
    public_key_group.add_argument('pk_1', help="Public key 1", widget="FileChooser", default="./test_data/other_pk_1.jwk")
    public_key_group.add_argument('pk_2', help="Public key 2", widget="FileChooser", default="./test_data/coffee_company_pk.jwk")
    public_key_group.add_argument('pk_3', help="Public key 3", widget="FileChooser", default="./test_data/other_pk_2.jwk")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["./target/release/prove", args.signed_pod, args.zk_pod, args.pk_1, args.pk_2, args.pk_3], env=env, capture_output=True, text=True)
    if output.returncode != 0:
        print("An error occurred.")
        print(output.stderr)
    else:
        print("Done")


if __name__ == "__main__":
    main()
