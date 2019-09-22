from cryptopals import cryptlib


class TestFirstSuite:
    # Challenge 1
    def test_hex_to_base(self):
        hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        assert (cryptlib.hex_to_base(hex_string) == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    # Challenge 2
    def test_fixedxor(self):
        plain = "1c0111001f010100061a024b53535009181c"
        key = "686974207468652062756c6c277320657965"
        assert (cryptlib.fixedxor(plain, key).hex() == "746865206b696420646f6e277420706c6179")

    # Challenge 3
    def test_singlebytexor(self):
        target = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        answ = cryptlib.attack_singlebytexor(target)["plain"]
        assert (answ == b"Cooking MC's like a pound of bacon")

    # Challenge 4
    def test_detect_singlebytexor(self):
        answ = cryptlib.detect_singlebytexor("res/4.txt")
        assert (answ == b"Now that the party is jumping\n")

    # Challenge 5
    def test_repeatxor(self):
        answ = cryptlib.xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b"ICE")
        assert (bytes.hex(answ) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
                                   "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

    # Challenge 6.1
    def test_haming(self):
        assert (cryptlib.haming(b"this is a test", b"wokka wokka!!!") == 37)

    # Challenge 6.2
    def test_attack_repeatingxor(self):
        with open("res/6.txt", "r") as f:
            result = cryptlib.attack_repeatingxor(f.read())
        assert (result["key"] == b"Terminator X: Bring the noise")

    # Challenge 7
    def test_aes_ecb(self):
        from base64 import b64decode
        key = b"YELLOW SUBMARINE"
        data = b64decode(open("res/7.txt", "r").read())
        plain = open("res/7_result.txt", "rb").read()
        decrypted_data = cryptlib.aes_decrypt_ecb(data, key, pad=False)
        assert (decrypted_data == plain)
        assert (cryptlib.aes_encrypt_ecb(plain, key) == data)

    # Challenge 8
    def test_detect_aes_ecb(self):
        encrypted_strings = list(map(bytes.fromhex, open("res/8.txt", "r").read().split('\n')[:-1]))
        result = cryptlib.detect_aec_ecb(encrypted_strings)
        assert (result[0]["count_replays"] == 3)
        assert (result[0]["index"] == 132)
