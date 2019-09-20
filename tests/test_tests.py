from cryptopals import cryptolib


class TestFirstSuite:
    # Challenge 1
    def test_hextobase64(self):
        hexString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        assert(cryptolib.hexToBase(hexString) == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    # Challenge 2
    def test_fixedxor(self):
        plain = "1c0111001f010100061a024b53535009181c"
        key = "686974207468652062756c6c277320657965"
        assert(cryptolib.fixedxor(plain, key) == "746865206b696420646f6e277420706c6179")

    # Challenge 3
    def test_singlebytexor(self):
        target = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        answ = cryptolib.attack_singlebytexor(target)["plain"]
        assert(answ == b"Cooking MC's like a pound of bacon")

    # Challenge 4
    def test_detect_singlebytexor(self):
        answ = cryptolib.detect_singlebytexor("res/4.txt")
        print(f"Plaintext is {answ}")
        assert(answ == b"Now that the party is jumping\n")

    # Challenge 5
    def test_repeatxor(self):
        answ = cryptolib.xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
        print(f"Ciphertext is {answ}")
        assert (bytes.hex(answ) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
                                        "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

    # Challenge 6.1
    def test_haming(self):
        assert(cryptolib.haming("this is a test", "wokka wokka!!!") == 37)

