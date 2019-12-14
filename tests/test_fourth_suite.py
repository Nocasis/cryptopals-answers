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
