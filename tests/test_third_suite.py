from cryptopals import cryplib


class TestFirstSuite:
    # Challenge 17
    def test_padding_oracle_attacl(self):
        assert(cryplib.padding_oracle_attack() is True)

