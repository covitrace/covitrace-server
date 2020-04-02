#!/usr/bin/env python3

import requests
import os
import time
import string
from hashlib import sha256
from random import randrange, choice

URL='http://127.0.0.1/v1/report/self'
URL='http://127.0.0.1:8000/v1/report/self'
POW_BITS = 18
REGIONS = ['2w4', '96r', 'tbg', '5my', 'sxx', 'h80', 'c89', '6v8', '7b5', '9kz']

def check_pow(data, bits):
    """ Verify that client computed proof of work. """
    assert bits <= 256
    m = (2**bits - 1) << (256 - bits)
    return int.from_bytes(sha256(data).digest(), byteorder='big') & m == 0

data = b''
for _ in range(randrange(3, 7)):
    region = choice(REGIONS).encode('utf-8')
    count = randrange(10, 30)
    l = count * 16 + len(region)
    data += bytes([l >> 8, l & 0xff])
    data += region
    for _ in range(count):
        data += os.urandom(16)

now = int(time.time())
now = now - (now % 3600)

nonce = os.urandom(8)
while not check_pow(nonce + data, POW_BITS):
    nonce = os.urandom(8)

data = nonce + data

r = requests.post(URL, data=data)
print("HTTP status code:", r.status_code)
print("HTTP body:", r.text)
