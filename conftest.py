from time import time
import pytest


@pytest.fixture(scope='class', autouse=True)
def suite_data():
    print("\n> Suite setup")
    yield
    print("> Suite teardown")

    
# @pytest.fixture(scope='function')
# def case_data_hexToBase():
#     print("   > Case setup")
#     yield "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
#     print("\n   > Case teardown")
