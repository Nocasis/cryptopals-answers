from cryptopals import cryptlib


class TestSecondSuite:
    # Challenge 9.1
    def test_pkcs7_pad(self):
        assert(cryptlib.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04")

    # Challenge 9.2
    def test_is_pkcs7_padded(self):
        assert(cryptlib.is_pkcs7_padded(b"YELLOW SUBMARINE") is False)
        assert(cryptlib.is_pkcs7_padded(b"YELLOW SUBMARINE\x01") is True)

    # Challenge 9.3
    def test_pkcs7_unpad(self):
        assert(cryptlib.pkcs7_unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04") == b"YELLOW SUBMARINE")