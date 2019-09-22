from itertools import cycle
import Crypto.Cipher
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


def hexToBase(hexstring: str) -> bytes:
    from base64 import b64encode
    return b64encode(bytes.fromhex(hexstring))


def fixedxor(plaintext: str, key: str) -> bytes:
    plain = bytes.fromhex(plaintext)
    key_value = bytes.fromhex(key)
    if len(plain) != len(key_value):
        return None
    return b"".join(bytes([plain[i] ^ key_value[i]]) for i in range(len(key_value))).hex()


def singlebytexor(text: str, key_char: int) -> bytes:
    try:
        return b"".join(bytes([char ^ key_char]) for char in bytes.fromhex(text))
    except TypeError:
        return b"".join(bytes([char ^ key_char]) for char in text)


def xor(text: str, key) -> bytes:
    try:
        return b"".join(bytes([ord(p) ^ ord(k)]) for (p, k) in zip(text, cycle(key)))
    except TypeError:
        return b"".join(bytes([p ^ k]) for (p, k) in zip(text, cycle(key)))


def count_score(target: bytes) -> float:
    score = 0
    for byte in target:
        score += FREQ.get(chr(byte).lower(), 0)
    return score


def attack_singlebytexor(text: str) -> dict:
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
        candidates.append(attack_singlebytexor(target))
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]["plain"]


def haming(src1: str, src2: str) -> int:
    dist = 0
    r = xor(src1, src2)
    for byte in r: dist += bin(byte).count('1')
    return dist


def attack_repeatingxor(data: str) -> dict:
    from base64 import b64decode
    from itertools import combinations
    data = b64decode(data)
    hamingdist = 0
    key_sizes = dict()
    for key_size in range(2, 41):

        blocks = [data[i:i + key_size] for i in range(0, len(data), key_size)][:4]
        blocks = list(combinations(blocks, 2))
        for pair in blocks:
            hamingdist += haming(*pair)
        hamingdist /= 6 * key_size
        key_sizes[key_size] = hamingdist
    true_keysize = sorted(key_sizes.items(), key=lambda x: x[1])[0][0]

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

    return ({"plain": xor(data, key), "key": key, "keysize": true_keysize})


def count_replays(data: bytes) -> int:
    block_size = Crypto.Cipher.AES.block_size
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    return len(blocks) - len(set(blocks))


def detect_aec_ecb(encrypted_strings: list) -> list:
    count = 1
    aes_strings_ecb = list()
    for s in encrypted_strings:
        current_count = count_replays(s)
        if count <= current_count:
            aes_strings_ecb.append({"data": s, "count_replays": current_count, "index": encrypted_strings.index(s)})
    return aes_strings_ecb


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if len(data) == block_size:
        return data
    pad_size = block_size - len(data)
    return data + bytes([pad_size]) * pad_size


def is_pkcs7_padded(data: bytes) -> bool:
    pad = data[-1]
    return all(pad == b for b in data[-pad:])


def pkcs7_unpad(data: bytes) -> bytes:
    if not is_pkcs7_padded(data):
        return data
    pad = data[-1]
    return data[:-pad]


def aes_decrypt_cbc(data: str, key: bytes, iv: bytes) -> bytes:
    decrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    for i in range(0, len(data), AES.block_size):
        current_block = data[i:i + AES.block_size]
        block = aes.decrypt(current_block)
        decrypted_data += xor(block, prev_block)
        prev_block = current_block
    return pkcs7_unpad(decrypted_data)


def aes_encrypt_cbc(data: str, key: bytes, iv: bytes) -> bytes:
    encrypted_data = bytes()
    aes = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    for i in range(0, len(data), AES.block_size):
        current_block = pkcs7_pad(data[i:i + AES.block_size], AES.block_size)
        block = aes.encrypt(xor(current_block, prev_block))
        encrypted_data += block
        prev_block = block
    return encrypted_data
