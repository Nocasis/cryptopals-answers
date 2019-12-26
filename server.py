from flask import Flask
from flask import request
from time import sleep

from cryptopals.cryplib import HmacSha1

app = Flask(__name__)


# env FLASK_APP=server.py flask run
KEY = b"YELLOW SUBMARINE"

#http://localhost:5000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
@app.route("/test", methods=['GET'])
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


def insecure_compare(s1, s2):
    for b1, b2 in zip(s1, s2):
        if b1 != b2:
            return False
        sleep(0.005)
        # TODO 0.005
    return True
