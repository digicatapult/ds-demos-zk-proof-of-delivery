import subprocess
import os
from gooey import Gooey, GooeyParser

@Gooey(program_name="Generate and sign a Proof of Delivery")
def main():

    tmp_claims_file_path = "delivery_claims.json"

    parser = GooeyParser(description="")
    pod_group = parser.add_argument_group(
        "Proof of Delivery details", 
        ""
    )
    pod_group.add_argument('issuer_id', help="Issuer ID", default="Coffee Chain 1")
    pod_group.add_argument('subject_id', help="Subject ID", default="Coffee Supplier")
    pod_group.add_argument('product', help="Product", default="raw coffee beans")
    pod_group.add_argument('quantity', help="Quantity (kg)", default="1000")
    pod_group.add_argument('cost', help="Cost (£)", default="4000.00")

    signing_group = parser.add_argument_group(
        "Signing details", 
        "Choose the private signing key with which to sign the Proof of Delivery"
    )
    signing_group.add_argument('sk', help="Private signing key", widget="FileChooser", default="./test_data/coffee_company_sk.jwk")
    signing_group.add_argument('signed_pod', help="Output Proof of Delivery file", widget="FileSaver", default="./" + "proof_of_delivery.jwt")

    args = parser.parse_args()

    output = subprocess.run(["./target/release/gen_delivery_claims_file", "--path-to-claims-file", tmp_claims_file_path, "--issuer-id", args.issuer_id, "--subject-id", args.subject_id, "--product", args.product, "--quantity", args.quantity, "--cost", args.cost])

    output = subprocess.run(["./target/release/sign_pod", args.sk, tmp_claims_file_path, args.signed_pod])
    if output.returncode != 0:
        print("An error occurred.")
        print(output.stderr)
    else:
        print("Done")

if __name__ == "__main__":
    main()
