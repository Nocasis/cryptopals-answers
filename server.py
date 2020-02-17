from flask import Flask
from flask import request
from time import sleep

from cryptopals.cryplib import HmacSha1
from cryptopals.cryplib import aes_ctr
from cryptopals.cryplib import random_bytes
import json

app = Flask(__name__)


# env FLASK_APP=server.py flask run
KEY = b"YELLOW SUBMARINE"


@app.route("/aes_ctr_encrypt_bitflipping", methods=['GET'])
def aes_ctr_encrypt():
    if len(request.args['cmd']) > 256:
        return "Size is too large"
    data = json.dumps({"cmd": request.args['cmd'], "isAdmin": False}).encode()
    nonce = random_bytes(8)
    answer = {'nonce': nonce.hex(), 'cmd': aes_ctr(data, KEY, nonce).hex()}
    return json.dumps(answer)



@app.route("/aes_ctr_decrypt", methods=['GET'])
def aes_ctr_decrypt():
    return aes_ctr(bytes.fromhex(request.args['cmd']), KEY, bytes.fromhex(request.args['nonce']))


@app.route("/aes_ctr_check_admin", methods=['GET'])
def aes_ctr_check_admin():
    data = json.loads(aes_ctr(bytes.fromhex(request.args['cmd']), KEY, bytes.fromhex(request.args['nonce'])))
    if not data['isAdmin']:
        return "Ha-ha, you aren't hacker!"
    else:
        return "Good job! Hacker Volodya?"


@app.route("/aes_ctr_encrypt_fixed_nonce", methods=['GET'])
def aes_ctr_encrypt_fixed_nonce():
    if len(request.args['cmd']) > 256:
        return "Size is too large"
    data = json.dumps({"cmd": request.args['cmd'], "isAdmin": False}).encode()
    # nonce = random_bytes(8)
    nonce = b'ssssssss'
    answer = {'nonce': nonce.hex(), 'cmd': aes_ctr(data, KEY, nonce).hex()}
    return str(answer)


# http://localhost:5000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
@app.route("/download", methods=['GET'])
def test():
    hmac = HmacSha1()
    data = request.args['file'].encode()
    signature = request.args['signature']
    to_verify = hmac.hmac(data, KEY).hex()
    if len(signature) != len(to_verify):
        return "Invalid sign size"
    result = insecure_compare(signature, to_verify)
    if result:
        return "Signature correct"
    assert False
    return {"sign": signature, "to_verify": to_verify.hex()}


@app.route("/", methods=['GET'])
def index():
    return "Hello, Friend."


def insecure_compare(s1, s2):
    for b1, b2 in zip(s1, s2):
        if b1 != b2:
            return False
        sleep(0.1)
        # TODO 0.005
    return True


if __name__ == '__main__':
    app.run()
