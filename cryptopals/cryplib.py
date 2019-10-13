from itertools import cycle
import Crypto.Cipher
from random import choice, randint
from Crypto.Cipher import AES

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


def is_pkcs7_padded(data: bytes, block_size: int) -> bool:
    is_full_block_of_padding_exist = all(block_size == b for b in data[-block_size:])
    is_correct_prev_last_padding = False
    if is_full_block_of_padding_exist:
        pad_size = data[-block_size - 1]
        is_correct_prev_last_padding = all(pad_size == b for b in data[-block_size-pad_size:-block_size])
    if not is_correct_prev_last_padding:
        raise PaddingError(data)
    return is_correct_prev_last_padding


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not is_pkcs7_padded(data, block_size):
        return data
    pad = data[-1 - block_size]
    return data[:-pad - block_size]


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
        return pkcs7_unpad(decrypted_data, AES.block_size)
    return decrypted_data


def aes_decrypt_ecb(data: bytes, key: bytes, pad=True) -> bytes:
    decrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), AES.block_size):
        current_block = data[i:i + AES.block_size]
        decrypted_data += aes.decrypt(current_block)
    if pad:
        return pkcs7_unpad(decrypted_data, AES.block_size)
    return decrypted_data


def aes_encrypt_cbc(plain: bytes, key: bytes, iv: bytes) -> bytes:
    encrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    need_padded_block = False
    for i in range(0, len(plain), AES.block_size):
        current_block = plain[i:i + AES.block_size]
        padded_block = pkcs7_pad(current_block, AES.block_size)
        if current_block != padded_block:
            current_block = padded_block
            need_padded_block = True
        block = aes.encrypt(xor(current_block, prev_block))
        encrypted_data += block
        prev_block = block
    if need_padded_block:
        return encrypted_data + aes.encrypt(bytes([AES.block_size]) * AES.block_size)
    return encrypted_data


def aes_encrypt_ecb(plain: bytes, key: bytes) -> bytes:
    encrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    need_padded_block = False
    for i in range(0, len(plain), AES.block_size):
        current_block = plain[i:i + AES.block_size]
        padded_block = pkcs7_pad(current_block, AES.block_size)
        if current_block != padded_block:
            current_block = padded_block
            need_padded_block = True
        encrypted_data += aes.encrypt(current_block)
    if need_padded_block:
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

    def remove_user(self, profile):
        if profile in self.users:
            self.users.remove(profile)


def cut_and_paste():
    key = random_bytes(AES.block_size)
    db = Database()
    user_profile = db.encode_profile("ssss@gmail.com").encode()
    encrypted_user = aes_encrypt_ecb(user_profile, key)

    admin_profile = db.encode_profile("s@mail.com" + "admin" + (bytes([11]) * 11).decode()).encode()
    encrypted_admin = aes_encrypt_ecb(admin_profile, key)
    hacked_string = encrypted_user[:AES.block_size * 2] + \
                    encrypted_admin[AES.block_size:AES.block_size * 2] + \
                    encrypted_user[-AES.block_size:]
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
        if first[i:i + AES.block_size] != second[i:i + key_size]:
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
