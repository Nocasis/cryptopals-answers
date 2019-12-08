from cryptopals import cryplib


class TestFirstSuite:
    # Challenge 17
    def test_padding_oracle_attack(self):
        assert(cryplib.padding_oracle_attack() is True)

    # Challenge 18
    def test_aes_ctr(self):
        from base64 import b64decode
        ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        decrypted = cryplib.aes_ctr(ciphertext, b"YELLOW SUBMARINE", bytes([0]) * 8, 1)
        assert decrypted == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    # Challenge 19.0
    def test_fixed_nonce_ctr_(self):
        from base64 import b64decode

        texts = list(map(b64decode, open("res/19.txt", "r").read().split("\n")))
        key = cryplib.random_bytes(16)
        ciphertext = [cryplib.aes_ctr(text, key, bytes([0]) * 8) for text in texts]
        maximum_len = max(list(map(len, ciphertext)))
        plain = bytes([0]) * maximum_len
        encrypted_plain = cryplib.aes_ctr(plain, key, bytes([0]) * 8)
        keystream = cryplib.xor(plain, encrypted_plain)
        flag = True
        for i in range(len(ciphertext)):
            hacked = cryplib.xor(ciphertext[i], keystream)
            if hacked != texts[i]:
                flag = False
        assert flag is True

    # Challenge 19.1
    def test_fixed_nonce_ctr(self):
        from base64 import b64decode
        texts = list(map(b64decode, open("res/19.txt", "r").read().split("\n")))
        key = cryplib.random_bytes(16)
        ciphertexts = [cryplib.aes_ctr(text, key, bytes([0]) * 8) for text in texts]
        maximum_len = max(list(map(len, ciphertexts)))

        # for debug
        plain = bytes([0]) * maximum_len
        encrypted_plain = cryplib.aes_ctr(plain, key, bytes([0]) * 8)
        keystream = cryplib.xor(plain, encrypted_plain)
        # end for debug

        # p1 + k = c1
        # c1 + c2 = p1 + p2

        decrypted_keystream = b""
        # decrypted_keystream = cryplib.xor(ciphertexts[0], b"I ")[:2]
        # decrypted_keystream = cryplib.xor(ciphertexts[27], b"He ")[2:3]
        # decrypted_keystream = cryplib.xor(ciphertexts[20], b"What ")[:len(b"What ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[1], b"Coming ")[:len(b"Coming ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[21], b"When you")[:len(b"When you")]
        # decrypted_keystream = cryplib.xor(ciphertexts[28], b"So sensitive")[:len(b"So sensitive")]
        # decrypted_keystream = cryplib.xor(ciphertexts[27], b"He might have")[:len(b"He might have")]
        # decrypted_keystream = cryplib.xor(ciphertexts[13], b"But lived where")[:len(b"But lived where")]
        # decrypted_keystream = cryplib.xor(ciphertexts[0], b"I have met them ")[:len(b"I have met them ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[4], b"I have passed with")[:len(b"I have passed with")]
        # decrypted_keystream = cryplib.xor(ciphertexts[12], b"Being certain that ")[:len(b"Being certain that ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[34], b"Yet I number him in ")[:len(b"Yet I number him in ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[15], b"A terrible beauty is ")[:len(b"A terrible beauty is ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[11], b"Around the fire at the")[:len(b"Around the fire at the")]
        # decrypted_keystream = cryplib.xor(ciphertexts[16], b"That woman's days were ")[:len(b"That woman's days were ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[12], b"Being certain that they ")[:len(b"Being certain that they ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[8], b"And thought before I had ")[:len(b"And thought before I had ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[35], b"He, too, has resigned his ")[:len(b"He, too, has resigned his ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[8], b"And thought before I had done")[:len(b"And thought before I had done")]
        # decrypted_keystream = cryplib.xor(ciphertexts[27], b"He might have won fame in the ")[:len(b"He might have won fame in the ")]
        # decrypted_keystream = cryplib.xor(ciphertexts[4], b"I have passed with a nod of the")[:len(b"I have passed with a nod of the")]
        # decrypted_keystream = cryplib.xor(ciphertexts[25], b"This other his helper and friend")[:len(b"This other his helper and friend")]
        # decrypted_keystream = cryplib.xor(ciphertexts[27], b"He might have won fame in the end")[:len(b"He might have won fame in the end")]
        # decrypted_keystream = cryplib.xor(ciphertexts[4], b"I have passed with a nod of the head")[:len(b"I have passed with a nod of the head")]
        decrypted_keystream = cryplib.xor(ciphertexts[37], b"He, too, has been changed in his turn,")[
                              :len(b"He, too, has been changed in his turn,")]

        assert decrypted_keystream == keystream

    def test_fixed_nonce_ctr_stat(self):
        from base64 import b64decode, b64encode
        texts = list(map(b64decode, open("res/19.txt", "r").read().split("\n")))
        key = cryplib.random_bytes(16)
        ciphertexts = {texts.index(text): cryplib.aes_ctr(text, key, bytes([0]) * 8) for text in texts}

        # for debug
        maximum_len = max(list(map(len, ciphertexts.values())))
        plain = bytes([0]) * maximum_len
        encrypted_plain = cryplib.aes_ctr(plain, key, bytes([0]) * 8)
        keystream = cryplib.xor(plain, encrypted_plain)
        # end for debug

        answer = {i: b'' for i in range(len(ciphertexts.values()))}
        not_empty_ciphertexts = {k: v for k, v in ciphertexts.items() if len(v) != 0}
        my_keystream = bytes()

        prev_min_len = 0
        for _ in range(len(ciphertexts.values())):
            not_empty_ciphertexts = {k: v for k, v in not_empty_ciphertexts.items() if len(v) != 0}
            try:
                min_len = min(map(len, not_empty_ciphertexts.values()))
            except ValueError:
                break

            concated = bytes()
            used_indexes = list()
            for k, v in not_empty_ciphertexts.items():
                concated += v[:min_len]
                used_indexes.append(k)
            concated_decrypted = cryplib.attack_repeatingxor(b64encode(concated))

            list_decrypted = [concated_decrypted['plain'][i:i + min_len] for i in
                              range(0, len(concated_decrypted['plain']), min_len)]
            j = 0
            for i in used_indexes:
                answer[i] += list_decrypted[j]
                j += 1

            not_empty_ciphertexts = {k: (v if len(v) > min_len else '') for k, v in not_empty_ciphertexts.items()}
            my_keystream += concated_decrypted['key'][prev_min_len:]
            prev_min_len = min_len

        assert keystream[:20] == my_keystream[:20]
        # print(answer)
