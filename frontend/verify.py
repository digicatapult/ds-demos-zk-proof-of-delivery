import subprocess
import os
from gooey import Gooey, GooeyParser

TMP_DIR="./"

@Gooey(program_name="Verify a Zero Knowledge Proof of Delivery")
def main():
    parser = GooeyParser(description="")
    proof_group = parser.add_argument_group("Proof to verify")
    proof_group.add_argument('zk_pod', help="Proof file", widget="FileChooser", default=TMP_DIR + "zk_pod.bin")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["../target/release/verify", args.zk_pod], env=env, capture_output=True, text=True)
    if output.returncode != 0:
        print("An error occurred.")
        print(output.stderr)
    else:
        print(output.stdout)


if __name__ == "__main__":
    main()
