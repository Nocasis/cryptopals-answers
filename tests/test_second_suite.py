from cryptopals import cryplib


class TestSecondSuite:
    # Challenge 9.1
    def test_pkcs7_pad(self):
        assert(cryplib.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04")

    # Challenge 9.2 and Challenge 15 also
    def test_is_pkcs7_padded(self):
        data = b"YELLOW SUBMARINE"
        block_size = cryplib.aes_block_size
        # assert(cryplib.is_pkcs7_padded(data, cryplib.aes_block_size) is False) TODO
        assert(cryplib.is_pkcs7_padded(data[:-1] + bytes([1])) is True)
        # assert(cryplib.is_pkcs7_padded(data[:-4] + bytes([5]) * 4 + padding_block, block_size) is False) TODO
        # assert(cryplib.is_pkcs7_padded(data[:-4] + b"\x01\x02\x03\x04" + padding_block, block_size) is False) TODO

    # Challenge 9.3
    def test_pkcs7_unpad(self):
        data = b"YELLOW SUBMARINE"
        block_size = cryplib.aes_block_size
        padded_data = data[:-1] + bytes([1])
        assert(cryplib.pkcs7_unpad(padded_data) == b"YELLOW SUBMARIN")

    # Challenge 10 TODO NIST test
    def test_aes_cbc(self):
        from base64 import b64decode
        key = b"YELLOW SUBMARINE"
        iv = b"\x00" * 16
        encrypted_origin = b64decode(open("res/10.txt", "r").read())
        decrypted = cryplib.aes_decrypt_cbc(encrypted_origin, key, iv)
        encrypted = cryplib.aes_encrypt_cbc(decrypted, key, iv)
        assert (encrypted_origin == encrypted)
        assert (decrypted == cryplib.aes_decrypt_cbc(encrypted, key, iv))

    # Challenge 11
    def test_detect_aes(self):
        from random import randint
        for _ in range(100):
            text = bytes([0]) * randint(60, 80)
            mode, ciphertext = cryplib.aes_encrypt_random(text)
            assert(mode == cryplib.aes_detect(ciphertext))

    # Challenge 12
    def test_byte_ecb_decryption_simple(self):
        from base64 import b64decode
        unknown_string = b64decode(open("res/12.txt", "rb").read())
        key = cryplib.random_bytes(16)
        cr = cryplib.byte_ecb_decryption_simple(unknown_string, key)
        assert(cr == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")

    # Challenge 13.1
    def test_parse_key_value(self):
        data = b"foo=bar&baz=qux&zap=zazzle"
        parsed = cryplib.parse_key_value(data)
        assert(parsed == {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'})

    # Challenge 13.2
    def test_cut_and_paste(self):
        hacked_profile = cryplib.cut_and_paste()
        parsed = cryplib.parse_key_value(hacked_profile)
        assert(parsed["role"] == "admin")

    # Challenge 14
    def test_byte_ecb_decryption_harder(self):
        from base64 import b64decode
        from random import randint
        unknown_string = b64decode(open("res/12.txt", "rb").read())
        key = cryplib.random_bytes(16)
        random_prefix = cryplib.random_bytes(randint(0, 64))
        cr = cryplib.byte_ecb_decryption_harder(random_prefix, unknown_string, key)
        assert(cr == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")

    # NIST Test for CBC
    def test_encryption_cbc(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        block_1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        block_2 = bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
        block_3 = bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")
        block_4 = bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")
        cblock_1 = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        cblock_2 = bytes.fromhex("5086cb9b507219ee95db113a917678b2")
        cblock_3 = bytes.fromhex("73bed6b8e3c1743b7116e69e22229516")
        cblock_4 = bytes.fromhex("3ff1caa1681fac09120eca307586e1a7")
        doc_in = block_1 + block_2 + block_3 + block_4
        encrypted = cryplib.aes_encrypt_cbc(doc_in, key, iv)
        from_doc = cblock_1 + cblock_2 + cblock_3 + cblock_4
        assert(cryplib.aes_decrypt_cbc(encrypted, key, iv) == cryplib.aes_decrypt_cbc(from_doc, key, iv, False))

    # Challenge 16
    def test_cbc_bitflipping_attck(self):
        assert(cryplib.cbc_bitflipping_attack() is True)
