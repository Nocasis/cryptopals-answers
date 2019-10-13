from cryptopals import cryplib


class TestSecondSuite:
    # Challenge 9.1
    def test_pkcs7_pad(self):
        assert(cryplib.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04")

    # Challenge 9.2 and Challenge 15 also
    def test_is_pkcs7_padded(self):
        data = b"YELLOW SUBMARINE"
        block_size = cryplib.aes_block_size
        padding_block = bytes([block_size])*block_size
        # assert(cryplib.is_pkcs7_padded(data, cryplib.aes_block_size) is False)
        assert(cryplib.is_pkcs7_padded(data[:-1] + bytes([1]) + padding_block, block_size) is True)
        # assert(cryplib.is_pkcs7_padded(data[:-4] + bytes([5]) * 4 + padding_block, block_size) is False)
        # assert(cryplib.is_pkcs7_padded(data[:-4] + b"\x01\x02\x03\x04" + padding_block, block_size) is False)

    # Challenge 9.3
    def test_pkcs7_unpad(self):
        data = b"YELLOW SUBMARINE"
        block_size = cryplib.aes_block_size
        padded_data = data[:-1] + bytes([1]) + bytes([block_size])*block_size
        assert(cryplib.pkcs7_unpad(padded_data, block_size) == b"YELLOW SUBMARIN")

    # Challenge 10 TODO NIST test
    def test_aes_cbc(self):
        from base64 import b64decode
        key = b"YELLOW SUBMARINE"
        iv = b"\x00" * 16
        encrypted_origin = b64decode(open("res/10.txt", "r").read())
        decrypted = cryplib.aes_decrypt_cbc(encrypted_origin, key, iv, pad=False)
        encrypted = cryplib.aes_encrypt_cbc(decrypted, key, iv)
        assert (encrypted_origin == encrypted)
        assert (decrypted == cryplib.aes_decrypt_cbc(encrypted, key, iv, pad=False))

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
    def test_byte_ecb_decryption_simple(self):
        from base64 import b64decode
        from random import randint
        unknown_string = b64decode(open("res/12.txt", "rb").read())
        key = cryplib.random_bytes(16)
        random_prefix = cryplib.random_bytes(randint(0, 64))
        cr = cryplib.byte_ecb_decryption_harder(random_prefix, unknown_string, key)
        assert(cr == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")

    # TODO Exception in padding