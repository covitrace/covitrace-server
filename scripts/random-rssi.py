#!/usr/bin/env python3

import requests
import os
import string
from hashlib import sha256
from random import randrange, choice

URL='http://127.0.0.1/v1/dev/rssi'
#URL='http://127.0.0.1:8000/v1/dev/rssi'
POW_BITS = 18

alphabet = string.ascii_letters + string.digits

def check_pow(data, bits):
    """ Verify that client computed proof of work. """
    assert bits <= 256
    m = (2**bits - 1) << (256 - bits)
    return int.from_bytes(sha256(data).digest(), byteorder='big') & m == 0

data = os.urandom(16)
data += bytes(ord(choice(alphabet)) for _ in range(randrange(5, 20))) + b"\0"
data += bytes(ord(choice(alphabet)) for _ in range(randrange(5, 30))) + b"\0"
data += str(randrange(10, 24000)).encode('utf-8')

nonce = os.urandom(8)
while not check_pow(nonce + data, POW_BITS):
    nonce = os.urandom(8)

data = nonce + data

r = requests.post(URL, data=data)
print("HTTP status code:", r.status_code)
print("HTTP body:", r.text)
