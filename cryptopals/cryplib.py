from base64 import b64decode
from itertools import cycle
import Crypto.Cipher
from random import choice, randint, getrandbits
from Crypto.Cipher import AES
from hashlib import sha1

FREQ = {
    "a": 8.167,
    "b": 1.492,
    "c": 2.782,
    "d": 4.253,
    "e": 12.702,
    "f": 2.228,
    "g": 2.015,
    "h": 6.094,
    "i": 6.966,
    "j": 0.153,
    "k": 0.772,
    "l": 4.025,
    "m": 2.406,
    "n": 6.749,
    "o": 7.507,
    "p": 1.929,
    "q": 0.095,
    "r": 5.987,
    "s": 6.327,
    "t": 9.056,
    "u": 2.758,
    "v": 0.978,
    "w": 2.360,
    "x": 0.150,
    "y": 1.974,
    "z": 0.074,
    ' ': 19.18182
}

aes_block_size = AES.block_size


def hex_to_base(hexstring: str) -> bytes:
    from base64 import b64encode
    return b64encode(bytes.fromhex(hexstring))


def fixedxor(plaintext: str, key: str) -> bytes:
    plain = bytes.fromhex(plaintext)
    key_value = bytes.fromhex(key)
    if len(plain) != len(key_value):
        return b""
    return b"".join(bytes([plain[i] ^ key_value[i]]) for i in range(len(key_value)))


def singlebytexor(text: bytes, key_char: int) -> bytes:
    return b"".join(bytes([char ^ key_char]) for char in text)


def xor(text: bytes, key: bytes) -> bytes:
    try:
        return b"".join(bytes([ord(p) ^ ord(k)]) for (p, k) in zip(text, cycle(key)))
    except TypeError:
        return b"".join(bytes([p ^ k]) for (p, k) in zip(text, cycle(key)))


def count_score(target: bytes) -> float:
    score = 0
    for byte in target:
        score += FREQ.get(chr(byte).lower(), 0)
    return score


def attack_singlebytexor(text: bytes) -> dict:
    higher_score = float()
    winner = b""
    key = b""
    for byte in range(256):
        candidate = singlebytexor(text, byte)
        candidate_score = count_score(candidate)
        if candidate_score > higher_score:
            higher_score = candidate_score
            winner = candidate
            key = byte
    return {"plain": winner, "score": higher_score, "key": key}


def detect_singlebytexor(filename: str):
    targets = open(filename, 'r').read().split("\n")
    candidates = list()
    for target in targets:
        candidates.append(attack_singlebytexor(bytes.fromhex(target)))
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]["plain"]


def haming(src1: bytes, src2: bytes) -> int:
    dist = 0
    r = xor(src1, src2)
    for byte in r:
        dist += bin(byte).count('1')
    return dist


def attack_repeatingxor(data: str) -> dict:
    from base64 import b64decode
    from itertools import combinations
    data = b64decode(data)
    haming_dist = 0
    key_sizes = dict()
    for key_size in range(2, 41):

        blocks = [data[i:i + key_size] for i in range(0, len(data), key_size)][:4]
        blocks = list(combinations(blocks, 2))
        for pair in blocks:
            haming_dist += haming(*pair)
        haming_dist /= 6 * key_size
        key_sizes[key_size] = haming_dist
    true_keysize, _ = sorted(key_sizes.items(), key=lambda x: x[1])[0]

    bytes_blocks = list()
    block = bytes()

    for i in range(true_keysize):
        for j in range(i, len(data), true_keysize):
            block += bytes([data[j]])
        bytes_blocks.append(block)
        block = bytes()

    key = bytes()
    for keychar in bytes_blocks:
        key += bytes([attack_singlebytexor(keychar)["key"]])

    return {"plain": xor(data, key), "key": key, "keysize": true_keysize}


def count_replays(data: bytes) -> int:
    block_size = Crypto.Cipher.AES.block_size
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    return len(blocks) - len(set(blocks))


def detect_aes_ecb(encrypted_strings: list) -> list:
    count = 1
    aes_strings_ecb = list()
    for s in encrypted_strings:
        current_count = count_replays(s)
        if count <= current_count:
            aes_strings_ecb.append({"data": s, "count_replays": current_count, "index": encrypted_strings.index(s)})
    return aes_strings_ecb


class PaddingError(Exception):
    def __init__(self, text):
        self.txt = text


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if len(data) == block_size:
        return data
    pad_size = block_size - len(data)
    return data + bytes([pad_size]) * pad_size


def is_pkcs7_padded(data: bytes) -> bool:
    padding = data[-1]
    is_correct = all(padding == b for b in data[-padding:])
    if not is_correct:
        # print(data)
        # print([(padding,b) for b in data[-padding:]])
        raise PaddingError(data)
    return is_correct


def pkcs7_unpad(data: bytes) -> bytes:
    if not is_pkcs7_padded(data):
        return data
    pad = data[-1]
    return data[:-pad]


def aes_decrypt_cbc(data: bytes, key: bytes, iv: bytes, pad=True) -> bytes:
    decrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    for i in range(0, len(data), AES.block_size):
        current_block = data[i:i + AES.block_size]
        block = aes.decrypt(current_block)
        decrypted_data += xor(block, prev_block)
        prev_block = current_block
    if pad:
        return pkcs7_unpad(decrypted_data)
    return decrypted_data


def aes_decrypt_ecb(data: bytes, key: bytes, pad=True) -> bytes:
    decrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), AES.block_size):
        current_block = data[i:i + AES.block_size]
        decrypted_data += aes.decrypt(current_block)
    if pad:
        return pkcs7_unpad(decrypted_data)
    return decrypted_data


def aes_encrypt_cbc(plain: bytes, key: bytes, iv: bytes) -> bytes:
    encrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    for i in range(0, len(plain), AES.block_size):
        current_block = plain[i:i + AES.block_size]
        padded_block = pkcs7_pad(current_block, AES.block_size)
        block = aes.encrypt(xor(padded_block, prev_block))
        encrypted_data += block
        prev_block = block
    if len(plain) % AES.block_size == 0:
        return encrypted_data + aes.encrypt(xor(bytes([AES.block_size]) * AES.block_size, prev_block))
    return encrypted_data


def aes_encrypt_ecb(plain: bytes, key: bytes) -> bytes:
    encrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(plain), AES.block_size):
        current_block = plain[i:i + AES.block_size]
        padded_block = pkcs7_pad(current_block, AES.block_size)
        encrypted_data += aes.encrypt(padded_block)
    if len(plain) % AES.block_size == 0:
        return encrypted_data + aes.encrypt(bytes([AES.block_size]) * AES.block_size)
    return encrypted_data


# it is not secure, just for task
def random_bytes(size: int) -> bytes:
    return b''.join(choice([bytes([i]) for i in range(256)]) for _ in range(size))


def pad_random_data(data: bytes) -> bytes:
    return b''.join(choice([bytes([i]) for i in range(256)]) for _ in range(randint(5, 11))) + \
           data + \
           b''.join(choice([bytes([i]) for i in range(256)]) for _ in range(randint(5, 11)))


def aes_encrypt_random(plain: bytes) -> (str, bytes):
    plain = pad_random_data(plain)
    if randint(0, 1):
        return "ECB", aes_encrypt_ecb(plain, random_bytes(16))
    else:
        return "CBC", aes_encrypt_cbc(plain, random_bytes(16), random_bytes(16))


def aes_detect(cipher_text: bytes) -> str:
    return "ECB" if count_replays(cipher_text) > 0 else "CBC"


def aes_detect_keysize_ecb(key: bytes, max_keysize=128) -> int:
    for size in range(1, max_keysize):
        tmp_plain = bytes([ord('A')]) * size
        tmp_ciphertext = aes_encrypt_ecb(tmp_plain, key)
        if count_replays(tmp_ciphertext) > 0:
            return int(size / 2)
    return 0


def next_byte_simple(block_size: int, curr_dec_msg: bytes, unknown_data: bytes, key: bytes):
    size_of_helping_vector = (block_size - (1 + len(curr_dec_msg))) % block_size
    prefix = bytes([0]) * size_of_helping_vector
    size = size_of_helping_vector + len(curr_dec_msg) + 1
    ciphertext = aes_encrypt_ecb(prefix + unknown_data, key)
    for i in range(256):
        fake_ciphertext = aes_encrypt_ecb(prefix + curr_dec_msg + bytes([i]) + unknown_data, key)
        if fake_ciphertext[:size] == ciphertext[:size]:
            return bytes([i])
    return b""


def byte_ecb_decryption_simple(unknown_data: bytes, key: bytes) -> bytes:
    secret = b""

    mode = aes_detect(aes_encrypt_ecb(bytes([0]) * 64 + unknown_data, key))
    if mode != "ECB":
        return b""

    key_size = aes_detect_keysize_ecb(key)
    unknown_data_size = len(unknown_data)
    for _ in range(unknown_data_size):
        secret += next_byte_simple(key_size, secret, unknown_data, key)

    return secret


def parse_key_value(data: bytes) -> dict:
    data = data.replace(b" ", b"")
    pairs = data.split(b"&")
    json_key_value = dict()
    for pair in pairs:
        key_value = pair.split(b"=")
        json_key_value[key_value[0].decode()] = key_value[1].decode()
    return json_key_value


class Database:
    def __init__(self):
        self.users = dict()

    def add_user(self, email):
        profile = self.profile_for(email)
        if not self.__is_user_exists(profile):
            self.users[len(self.users)] = profile

    def __is_user_exists(self, profile):
        exist = False
        for prof in self.users.values():
            if prof["email"] == profile["email"]:
                exist = True
        return exist

    def profile_for(self, email):
        try:
            email = email.replace("&", "").replace("=", "")
            profile = {"email": email, "uid": len(self.users), "role": "user"}
            return profile
        except Exception:
            return {"email": "error@gmail.com", "uid": len(self.users), "role": "user"}

    def encode_profile(self, email):
        profile = self.profile_for(email)
        user_profile = ""
        for k, v in profile.items():
            user_profile += f"{k}={v}&"
        return user_profile[:-1]


def cut_and_paste():
    key = random_bytes(AES.block_size)
    db = Database()
    user_profile = db.encode_profile("ssss@gmail.com").encode()
    encrypted_user = aes_encrypt_ecb(user_profile, key)
    admin_profile = db.encode_profile("s@mail.com" + "admin" + (bytes([11]) * 11).decode()).encode()
    encrypted_admin = aes_encrypt_ecb(admin_profile, key)
    hacked_string = encrypted_user[:AES.block_size * 2] + \
                    encrypted_admin[AES.block_size:AES.block_size * 2]
    hacked_profile = aes_decrypt_ecb(hacked_string, key)
    return hacked_profile


def next_byte_harder(rand_prefix_size: int, block_size: int, curr_dec_msg: bytes,random_prefix: bytes, unknown_data: bytes, key: bytes):
    size_of_helping_vector = (block_size - rand_prefix_size - (1 + len(curr_dec_msg))) % block_size
    prefix = bytes([0]) * size_of_helping_vector
    size = size_of_helping_vector + len(curr_dec_msg) + 1 + rand_prefix_size
    ciphertext = aes_encrypt_ecb(random_prefix + prefix + unknown_data, key)
    for i in range(256):
        fake_ciphertext = aes_encrypt_ecb(random_prefix + prefix + curr_dec_msg + bytes([i]) + unknown_data, key)
        if fake_ciphertext[:size] == ciphertext[:size]:
            return bytes([i])
    return b""


def get_random_prefix_size(random_prefix: bytes, unknown_data: bytes, key: bytes, key_size: int):
    first = aes_encrypt_ecb(random_prefix + unknown_data, key)
    second = aes_encrypt_ecb(random_prefix + bytes([0]) + unknown_data, key)
    random_prefix_size = 0
    for i in range(0, len(second), key_size):
        if first[i:i + key_size] != second[i:i + key_size]:
            random_prefix_size = i
            break
    for i in range(key_size):
        test = bytes([0])*(2 * key_size + i)
        test_encryption = aes_encrypt_ecb(random_prefix + test + unknown_data, key)
        if count_replays(test_encryption) > 0:
            return random_prefix_size + key_size - i if i is not 0 else random_prefix_size


def byte_ecb_decryption_harder(random_prefix: bytes, unknown_data: bytes, key: bytes) -> bytes:
    secret = b""

    mode = aes_detect(aes_encrypt_ecb(random_prefix + bytes([0]) * 64 + unknown_data, key))
    if mode != "ECB":
        return b""

    key_size = aes_detect_keysize_ecb(key)
    random_prefix_size = get_random_prefix_size(random_prefix, unknown_data, key, key_size)
    unknown_data_size = len(unknown_data)
    for _ in range(unknown_data_size):
        secret += next_byte_harder(random_prefix_size, key_size, secret, random_prefix, unknown_data, key)

    return secret


def get_user_data(userdata: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    sufix = b";comment2=%20like%20a%20pound%20of%20bacon"
    return prefix + userdata.replace(b"=", b"").replace(b";", b"") + sufix


def is_admin_in_data(encrypted: bytes, key: bytes, iv: bytes):
    decrypted = aes_decrypt_cbc(encrypted, key, iv)
    return b";admin=true;" in decrypted


def get_prefix_size(key: bytes, iv: bytes):
    block_size = len(key)
    first = aes_encrypt_cbc(get_user_data(b""), key, iv)
    second = aes_encrypt_cbc(get_user_data(bytes([0])), key, iv)
    prefix_size = 0
    for i in range(0, len(second), block_size):
        if first[i:i + block_size] != second[i:i + block_size]:
            prefix_size = i
            break
    for i in range(block_size + 1):
        first = bytes([0]) * i + bytes([1])
        second = bytes([0]) * i + bytes([2])
        enc_first = aes_encrypt_cbc(get_user_data(first), key, iv)
        enc_second = aes_encrypt_cbc(get_user_data(second), key, iv)
        if enc_first[prefix_size:prefix_size + block_size] == enc_second[prefix_size:prefix_size + block_size]:
            return prefix_size + (block_size - i)


def cbc_bitflipping_attack():
    block_size = AES.block_size
    key = random_bytes(block_size)
    iv = random_bytes(block_size)
    data = get_user_data(b"hack.admin.true.")
    encrypted = aes_encrypt_cbc(data, key, iv)
    prefix_size = get_prefix_size(key, iv)
    encrypted = encrypted[:prefix_size + len("hack")-block_size] + \
                bytes([encrypted[prefix_size + len("hack") - block_size] ^ ord(".") ^ ord(";")]) + \
                encrypted[prefix_size + len("hack") + 1 - block_size:]

    encrypted = encrypted[:prefix_size + len("hack;admin") - block_size] + \
                bytes([encrypted[prefix_size + len("hack;admin") - block_size] ^ ord(".") ^ ord("=")]) + \
                encrypted[prefix_size + len("hack;admin") + 1 - block_size:]

    encrypted = encrypted[:prefix_size + len("hack;admin=true") - block_size] + \
                bytes([encrypted[prefix_size + len("hack;admin=true") - block_size] ^ ord(".") ^ ord(";")]) + \
                encrypted[prefix_size + len("hack;admin=true") + 1 - block_size:]
    is_admin = is_admin_in_data(encrypted, key, iv)
    return is_admin


class PaddingOracleAttack:
    def __init__(self):
        self.key = random_bytes(AES.block_size)
        self.iv = random_bytes(AES.block_size)

    def encrypt(self, plain):
        return aes_encrypt_cbc(plain, self.key, self.iv), self.iv

    def decrypt_and_validate_padding(self, cipher: bytes, iv_: bytes):
        decrypted = aes_decrypt_cbc(cipher, self.key, iv_, pad=False)
        try:
            return is_pkcs7_padded(decrypted)
        except PaddingError:
            return False


def choice_random_string_from_file(filename: str):
    strings = open(filename, "r").read()
    strings = strings.split("\n")
    return b64decode(strings[choice(range(len(strings)))])


def gen_fake_prev_block(prev_block: bytes, current_byte: int, padding_len: int, found_plain: bytes) ->bytes:
    char_index = len(prev_block) - padding_len

    char = current_byte ^ prev_block[char_index] ^ padding_len

    fake_prev = prev_block[:char_index] + bytes([char])
    block_size = 16
    j = 0
    for i in range(block_size - padding_len + 1, block_size):
        forced_char = prev_block[i] ^ found_plain[j] ^ padding_len
        fake_prev += bytes([forced_char])
        j += 1
    return fake_prev


def padding_oracle_attack():
    blackbox = PaddingOracleAttack()
    plain = choice_random_string_from_file("res/17.txt")
    encryped, iv = blackbox.encrypt(plain)
    ciphertext = [encryped[i:i + AES.block_size] for i in range(0, len(encryped), AES.block_size)]
    prepared_ciphertext = [iv] + ciphertext

    our_plain = b""
    for block_index in range(1, len(prepared_ciphertext)):
        block_plain = b""
        for pad_len in range(1, AES.block_size + 1):
            tmp_bytes = b""
            last_byte = b""
            for i in range(256):
                fake_prev_block = gen_fake_prev_block(prepared_ciphertext[block_index - 1], i, pad_len, block_plain)
                is_fail = blackbox.decrypt_and_validate_padding(prepared_ciphertext[block_index], fake_prev_block)
                if is_fail:
                    tmp_bytes += bytes([i])
            if len(tmp_bytes) == 1:
                last_byte = tmp_bytes
                block_plain = last_byte + block_plain
                continue
            for byte in tmp_bytes:
                for i in range(256):
                    fake_prev_block = gen_fake_prev_block(prepared_ciphertext[block_index - 1], i, pad_len + 1,
                                                          bytes([byte]) + block_plain)
                    is_fail = blackbox.decrypt_and_validate_padding(prepared_ciphertext[block_index], fake_prev_block)
                    if is_fail:
                        last_byte = bytes([byte])
                        break
            block_plain = last_byte + block_plain

        our_plain += block_plain
    return pkcs7_unpad(our_plain) == plain


def gen_big_num():
    return getrandbits(256)


def diffie_hellman(p: int, g: int) -> bool:
    a = gen_big_num() % p
    b = gen_big_num() % p
    A = power(g, a, p)  # public key
    B = power(g, b, p)  # public key
    s1 = power(B, a, p)  # session
    s2 = power(A, b, p)  # session
    return s1 == s2


def hex_to_int(hex_string: str) -> int:
    return int(hex_string, 16)


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\0'


def power(x: int, y: int, p: int) -> int:
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res


class Client:
    def __init__(self, p_: int, g_: int):
        self.p = p_
        self.g = g_
        self.private_key = gen_big_num() % self.p  # a
        self.public_key = power(self.g, self.private_key, self.p)  # A
        self.session = int()

    def make_session(self, pub_key: int):
        self.session = power(pub_key, self.private_key, self.p)

    def send_msg(self, msg: bytes):
        hash_sha1 = sha1()
        iv = random_bytes(16)  # AES.block_sie
        s = int_to_bytes(self.session)
        hash_sha1.update(s)
        sign = hash_sha1.hexdigest()
        return aes_encrypt_cbc(msg, sign[:16], iv) + iv

    def decrypt_msg(self, msg: bytes):
        hash_sha1 = sha1()
        iv = msg[-16:]
        encrypted_msg = msg[:-16]
        s = int_to_bytes(self.session)
        hash_sha1.update(s)
        sign = hash_sha1.hexdigest()
        return aes_decrypt_cbc(encrypted_msg, sign[:16], iv)


def normal_flow():
    p = """ffffffffffffffffffffffffffff"""
    p = hex_to_int(p)
    g = 2

    alice = Client(p, g)
    bob = Client(alice.p, alice.g)
    bob.make_session(alice.public_key)
    alice.make_session(bob.public_key)

    msg = b"hello"
    alices_msg = alice.send_msg(msg)
    bobs_msg = bob.send_msg(msg)

    return alice.decrypt_msg(bobs_msg) == bob.decrypt_msg(alices_msg)


def mitm_flow():
    p = """ffffffffffffffffffffffffffff"""
    p = hex_to_int(p)
    g = 2

    alice = Client(p, g)
    bob = Client(alice.p, alice.g)
    bob.make_session(alice.p)
    alice.make_session(bob.p)

    msg = b"hello"
    alices_msg = alice.send_msg(msg)
    bobs_msg = bob.send_msg(msg)

    alice_decrypt = alice.decrypt_msg(bobs_msg)
    bob_decrypt = bob.decrypt_msg(alices_msg)

    iv = alices_msg[-16:]
    encrypted_msg = alices_msg[:-16]
    hash_sha1 = sha1()
    hash_sha1.update(b'\x00')
    sign = hash_sha1.hexdigest()
    hacked_decrypt = aes_decrypt_cbc(encrypted_msg, sign[:16], iv)
    return hacked_decrypt == alice_decrypt == bob_decrypt


def g_equal_one():
    p = """ffffffff"""
    p = hex_to_int(p)
    g = 1

    alice = Client(p, g)
    bob = Client(alice.p, alice.g)
    bob.make_session(alice.public_key)
    alice.make_session(bob.public_key)

    msg = b"hello"
    alices_msg = alice.send_msg(msg)
    bobs_msg = bob.send_msg(msg)

    alice_decrypt = alice.decrypt_msg(bobs_msg)
    bob_decrypt = bob.decrypt_msg(alices_msg)

    iv = alices_msg[-16:]
    encrypted_msg = alices_msg[:-16]
    hash_sha1 = sha1()
    hash_sha1.update(b'\x01')
    sign = hash_sha1.hexdigest()
    hacked_decrypt = aes_decrypt_cbc(encrypted_msg, sign[:16], iv)
    return alice_decrypt == hacked_decrypt


def g_equal_p():
    p = """ffffffff"""
    p = hex_to_int(p)
    g = p

    alice = Client(p, g)
    bob = Client(alice.p, alice.g)
    bob.make_session(alice.public_key)
    alice.make_session(bob.public_key)

    msg = b"hello"
    alices_msg = alice.send_msg(msg)
    bobs_msg = bob.send_msg(msg)

    alice_decrypt = alice.decrypt_msg(bobs_msg)
    bob_decrypt = bob.decrypt_msg(alices_msg)

    iv = alices_msg[-16:]
    encrypted_msg = alices_msg[:-16]
    hash_sha1 = sha1()
    hash_sha1.update(b'\x00')
    sign = hash_sha1.hexdigest()
    hacked_decrypt = aes_decrypt_cbc(encrypted_msg, sign[:16], iv)
    return alice_decrypt == hacked_decrypt


def g_equal_p_minus_one():
    p = 25566665
    g = p-1
    alice = Client(p, g)
    bob = Client(alice.p, alice.g)
    bob.make_session(alice.public_key)
    alice.make_session(bob.public_key)
    msg = b"hello"
    alices_msg = alice.send_msg(msg)
    bobs_msg = bob.send_msg(msg)

    alice_decrypt = alice.decrypt_msg(bobs_msg)
    bob_decrypt = bob.decrypt_msg(alices_msg)

    hash_sha1 = sha1()
    iv = alices_msg[-16:]
    encrypted_msg = alices_msg[:-16]
    if alice.public_key == g and bob.public_key == g:
        s = int_to_bytes(g)
        hash_sha1.update(s)
        sign = hash_sha1.hexdigest()
        hacked_decrypt = aes_decrypt_cbc(encrypted_msg, sign[:16], iv)
    else:
        s = int_to_bytes(g)
        hash_sha1.update(b"\x01")
        sign = hash_sha1.hexdigest()
        hacked_decrypt = aes_decrypt_cbc(encrypted_msg, sign[:16], iv)
    return hacked_decrypt == alice_decrypt
