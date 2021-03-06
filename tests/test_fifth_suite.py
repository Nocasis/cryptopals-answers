from cryptopals import cryplib


class TestFirstSuite:
    # Challenge 33
    def test_diffie_hellman(self):
        p = """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"""
        p = cryplib.hex_to_int(p)
        g = 2
        assert(cryplib.diffie_hellman(p, g) is True)

    # Challenge 34.1
    def test_normal_flow(self):
        assert cryplib.normal_flow() is True

    # Challenge 34.2
    def test_mitm_flow(self):
        assert cryplib.mitm_flow() is True

    # Challenge 35.1
    def test_g_equal_one(self):
        assert cryplib.g_equal_one() is True

    # Challenge 35.2
    def test_g_equal_p(self):
        assert cryplib.g_equal_p() is True

    # Challenge 35.3
    def test_g_equal_p_minus_one(self):
        assert cryplib.g_equal_p_minus_one() is True