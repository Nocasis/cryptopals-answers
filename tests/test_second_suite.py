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

    # Challenge 10
    def test_aes_cbc(self):
        from base64 import b64decode
        key = b"YELLOW SUBMARINE"
        iv = b"\x00" * 16
        encrypted_origin = b64decode(open("res/10.txt", "r").read())
        decrypted = cryptlib.aes_decrypt_cbc(encrypted_origin, key, iv)
        encrypted = cryptlib.aes_encrypt_cbc(decrypted, key, iv)
        assert (encrypted_origin == encrypted)
        assert (decrypted == cryptlib.aes_decrypt_cbc(encrypted, key, iv))

    # Challenge 11
    def test_detect_aes(self):
        from random import randint
        for _ in range(100):
            text = bytes([0]) * randint(60, 80)
            mode, ciphertext = cryptlib.aes_encrypt_random(text)
            assert(mode == cryptlib.aes_detect(ciphertext))
