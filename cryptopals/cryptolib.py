from itertools import cycle


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

def fixedxor(plaintext: str, key: str) -> str:
    plain = bytes.fromhex(plaintext)
    key_value = bytes.fromhex(key)
    if len(plain) != len(key_value):
        return None
    from base64 import b64encode
    return b"".join(bytes([plain[i] ^ key_value[i]]) for i in range(len(key_value))).hex()

def singlebytexor(text: str, key_char: int) -> dict:
    return b"".join(bytes([char ^ key_char]) for char in bytes.fromhex(text))

def xor(text: str, key: str) -> str:
    return b"".join(bytes([ord(p) ^ ord(k)]) for (p,k) in zip(text, cycle(key)))

def attack_singlebytexor(text: str) -> bytes:
    higher_score = float()
    winner = b""
    for byte in range(256):
        candidate = singlebytexor(text, byte)
        candidate_score = count_score(candidate)
        if candidate_score > higher_score:
            higher_score = candidate_score
            winner = candidate
    return {"plain": winner, "score": higher_score}

def detect_singlebytexor(filename: str):
    targets = open(filename, 'r').read().split("\n")
    candidates = list()
    for target in targets:
        candidates.append(attack_singlebytexor(target))
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]["plain"]

def haming(src1: str, src2: str) -> int:
    if len(src1) != len(src2):
        return None
    dist = 0
    r = xor(src1, src2)
    for byte in r: dist += bin(byte).count('1')
    return dist

def count_score(target: bytes) -> float:
    score = 0
    for byte in target:
        score += FREQ.get(chr(byte).lower(), 0)
    return score


