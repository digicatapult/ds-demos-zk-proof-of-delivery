import os

# The Python code in this repo simply presents a GUI for the CLI rust tool so we
# just test the test data (default files) exist, which via the GitHub action
# forces the developer to ensure that any changes to the test data are
# propagated to the GUIs

def test_gen_and_sign_pod():
    assert os.path.exists("../test_data/coffee_company_sk.jwk")

def test_prove():
    assert os.path.exists("../test_data/other_pk_1.jwk")
    assert os.path.exists("../test_data/other_pk_2.jwk")
    assert os.path.exists("../test_data/coffee_company_pk.jwk")

def test_verify():
    assert True