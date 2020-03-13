from flask import Flask
from flask import request
from flask import send_file
from flask import make_response
from time import sleep

from cryptopals.cryplib import HmacSha1
from cryptopals.cryplib import aes_ctr
from cryptopals.cryplib import random_bytes
from cryptopals.cryplib import KeyedmacSha1
import json
import base64

app = Flask(__name__)


# env FLASK_APP=server.py flask run
KEY = b"YELLOW SUBMARINE"
MAC_KEY = b"YELLOW SUBMARINN"

# CRYPTO


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


# HASH

# http://localhost:5000/download?file=secret_file.txt&signature=a9691f4dd257353e548758737cdc5cf3e3bd2b7c
@app.route("/download", methods=['GET'])
def test():

    if not request.cookies.get('Admin-Cookie'):
        return "You have not rights to do this!"
    hmac = HmacSha1()
    if hmac.hmac(b"admin", KEY).hex() != request.cookies.get('Admin-Cookie'):
        return "You have not admin rights!"
    if not request.args['file'] or not request.args['signature']:
        return "Make GET /download?file=filename&signature=sign"
    data = request.args['file'].encode()
    print(data.decode())
    if data.decode() != "secret_file.txt":
        return "File doesn't exist."
    signature = request.args['signature']
    to_verify = hmac.hmac(data, KEY).hex()
    print(to_verify)
    if len(signature) != len(to_verify):
        return "Invalid sign size"
    result = insecure_compare(signature, to_verify)
    if result:
        return send_file("res/secret_file.txt", as_attachment=True)

    return {"sign": signature, "to_verify": to_verify.hex()}


# Admin-Cookie=d2aa3b282ad46d734e98b6bfd522f82fcdb29017
@app.route("/admin_login", methods=['POST', 'GET'])
def admin_login():
    admin_pass = "ldVZgRMbUBFrLQCfXQwMnqlGVcreXmyxxwArWVur"
    if request.method != 'POST':
        return "Only POST supported." \
               "Make post json {\"login\":\"test\",\"password\":\"test\"}," \
               "Content-Type: application/json"
    hmac = HmacSha1()
    # request.headers.get('your-header-name')
    json_data = request.get_json()
    login = json_data.get("login")
    otp = json_data.get("otp")
    if not login or not otp:
        return "Invalid login or otp"

    if login == "test" and otp == "test":
        res = make_response()
        to_verify = hmac.hmac(login.encode(), KEY).hex()
        res.set_cookie("Admin-Cookie", to_verify)
        return res

    if login == "admin" and otp == admin_pass:
        res = make_response()
        to_verify = hmac.hmac(login.encode(), KEY).hex()
        res.set_cookie("Admin-Cookie", to_verify)
        return res

    return "Invalid login or otp"


@app.route("/login", methods=['POST'])
def login_v2():
    json_data = request.get_json()
    login = json_data.get("login")
    password = json_data.get("password")
    if not login or not password:
        return "Invalid login or password"
    sha1_keyed = KeyedmacSha1(MAC_KEY)
    plain = f"login={login};password={password}"
    token = sha1_keyed.digest(plain.encode())
    info = {'data': base64.b64encode(plain.encode()).decode(), 'token': token}
    # return info
    return json.dumps(info)


@app.route("/get_admin_info", methods=['POST'])
def get_admin_info():
    json_data = request.get_json()
    plain = json_data.get("data")
    token = json_data.get("token")
    if not plain or not token:
        return "Empty data?"
    plain = base64.b64decode(plain)
    print(plain)
    token = token
    sha1_keyed = KeyedmacSha1(MAC_KEY)
    print(sha1_keyed.digest(plain))
    if sha1_keyed.validate(plain, token):
        if b";admin=true" in plain:
            return "Good job!"
        return "You aren't admin!"
    return "Token validation failed"


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
