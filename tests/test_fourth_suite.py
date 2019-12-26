from cryptopals import cryplib


class TestFourthSuite:
    # Challenge 25
    def test_random_access_ctr(self):
        plain = open("res/7_result.txt", "rb").read()
        oracle = cryplib.CtrOracle()
        ciphertext = oracle.encrypt(plain)
        keystream = oracle.edit(ciphertext, 0, bytes([0]) * len(ciphertext))
        decrypted_plain = cryplib.xor(ciphertext, keystream)
        print(decrypted_plain)

    # Challenge 26
    def test_bitflipping_ctr(self):
        oracle = cryplib.CtrBitOracle()
        token = oracle.get_user_data(b"hack.admin.true")
        fake_token = oracle.get_user_data(b"")
        prefix_size = 0
        while token[:prefix_size] == fake_token[:prefix_size]:
            prefix_size += 1
        token = token[:prefix_size + len('hack') - 1] + bytes(
            [token[prefix_size + len('hack') - 1] ^ ord('.') ^ ord(';')]) + \
                token[prefix_size + len('hack'):prefix_size + len('hack;admin') - 1] + bytes(
            [token[prefix_size + len('hack;admin') - 1] ^ ord('.') ^ ord('=')]) + \
                token[prefix_size + len('hack;admin=') - 1:]
        assert oracle.is_admin_in_data(token) is True

    # Challange 27
    def test_recover_key_attack(self):
        oracle = cryplib.RecoverKeyOracle()
        block_size = cryplib.AES.block_size
        ciphertext = oracle.encrypt(b's' * block_size + b'c' * block_size + b'r' * block_size)
        status, fail_plain = oracle.decrypt(ciphertext[:block_size] + bytes([0]) * block_size + ciphertext[:block_size])
        if not status:
            key = cryplib.xor(fail_plain[:block_size], fail_plain[-block_size:])
        assert key == oracle.key

    # Challange 29
    def test_length_extension_attack(self):
        import struct
        sha1_keyed = cryplib.KeyedmacSha1()
        plain = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        new_msg = b";admin=true"
        token = sha1_keyed.digest(plain)

        for key_size in range(17):
            fake_msg = cryplib.padding(bytes([0]) * key_size + plain)[key_size:] + new_msg
            h = list(struct.unpack('>5I', bytes.fromhex(token)))
            sha1 = cryplib.SHA1(h)
            sha1.update(new_msg, (key_size + len(fake_msg)) * 8)
            fake_token = sha1.hexdigest()

            if sha1_keyed.validate(fake_msg, fake_token):
                break
        assert sha1_keyed.validate(fake_msg, fake_token)
