#!/usr/bin/env python3

"""
covitrace-server: CoviTrace API server
Copyright (C) 2020 a8x9

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, request, jsonify, abort, make_response
from hashlib import sha256
from datetime import datetime
from binascii import unhexlify
import psycopg2
import time
import calendar
import ipaddress
import hmac


COVITRACE_DEV = False
HMAC_SECRET = unhexlify('4b4edb09bc4c06e3e4eb3057eb81c049')

# valid intervals for data fetching: 3 hour, 1 day
VALID_INTERVALS = sorted([ 10800, 86400 ])
VALID_REGION    = '0123456789bcdefghjkmnpqrstuvwxyz'  # base32

CACHE_TIME      = 604800  # 1 week
DELTA_TIME      = 60      # make sure latest reports get time to be inserted into DB
                          # before switching to next time window

NONCE_SIZE        = 8     # 64 bits
VALUE_SIZE        = 16    # 128 bits
REGION_SIZE       = 3     # geohash with 3 char precision
RETENTION_PERIOD  = 21    # days

MAX_REPORT_SIZE   = NONCE_SIZE + (RETENTION_PERIOD * 24 * 3) * (VALUE_SIZE + REGION_SIZE + 2)
MIN_REPORT_SIZE   = NONCE_SIZE + REGION_SIZE + 2 + VALUE_SIZE

MAX_RSSI_SIZE     = NONCE_SIZE + VALUE_SIZE + 31 + 41 + 1
MIN_RSSI_SIZE     = NONCE_SIZE + VALUE_SIZE + 2 + 2 + 1

MAX_REPORT_PER_IP = 3     # IP is only recorded for self-reports in order to limit spam
POW_BITS = 24


app = Flask(__name__)
conn = None


validregion = lambda region: len(region) == REGION_SIZE and all([e in VALID_REGION for e in region])


def datasize(data):
    """ Extract data prefixed by 16-bit big endian size """
    l = data[0] << 8 | data[1]
    d1 = data[2:2+l]
    d2 = data[2+l:]
    if len(d1) != l:
        raise IndexError
    return d1, d2


def select(table, region, start, end):
    query = 'SELECT value FROM {} WHERE region = %s AND stime >= %s AND stime <= %s'.format(table)
    start = datetime.utcfromtimestamp(start)
    end = datetime.utcfromtimestamp(end)
    data = None
    with conn.cursor() as curs:
        curs.execute(query, (region, start, end))
        data = b''.join(bytes(row[0]) for row in curs)
    return data


def data(table, region, interval, start):
    # check parameters validity
    now = int(time.time())
    if interval not in VALID_INTERVALS or start % interval or \
            (interval > VALID_INTERVALS[0] and start + interval > now) or \
            not validregion(region):
        return '', 400

    # do not send back data window which is not completed
    # only return data which can be cached by CDN
    if not COVITRACE_DEV and start + interval + DELTA_TIME > now:
        return '', 503

    # get data from database
    try:
        resp = make_response(select(table, region, start, start+interval), 200)
    except:
        return '', 500

    # set content-type and cache header to take advantage of proxy / CDN caching
    resp.headers['Content-Type'] = 'application/octet-stream'
    resp.headers['Cache-Control'] = 'max-age={}'.format(CACHE_TIME)

    return resp


@app.route('/v1/data/self/<string:region>/<int:interval>/<int:start>', methods=['GET'])
def sdata(region, interval, start):
    """
    Returns self-reports in region `region` from timestamp `start` to `start+interval`
    """
    return data('sreport', region, interval, start)


@app.route('/v1/data/hospital/<string:region>/<int:interval>/<int:start>', methods=['GET'])
def hdata(region, interval, start):
    """
    Returns hospital-reports in region `region` from timestamp `start` to `start+interval`
    """
    return data('hreport', region, interval, start)


def check_pow(data, bits):
    """ Verify that client computed proof of work. """
    assert bits <= 256
    m = (2**bits - 1) << (256 - bits)
    return int.from_bytes(sha256(data).digest(), byteorder='big') & m == 0


def get_client_ip():
    if 'CF-Connecting-IP' in request.headers:
        return request.headers['CF-Connecting-IP']
    elif 'X-Forwarded-For' in request.headers:
        return [ip.strip() for ip in request.headers['X-Forwarded-For'].split(',')][0]
    elif 'X-Real-IP' in request.headers:
        return request.headers['X-Real-IP']
    elif 'True-Client-IP' in request.headers:
        return request.headers['True-Client-IP']
    elif request.remote_addr:
        return request.remote_addr
    else:
        return '0.0.0.0'


def insert_sip(sip, stime):
    query = 'INSERT INTO siphash VALUES (%s, %s)'
    with conn.cursor() as curs:
        try:
            curs.execute(query, (sip, stime))
            return curs.statusmessage == 'INSERT 0 1'
        except:
            # allow more than 1 insert per VALID_INTERVALS[0] in dev mode
            return COVITRACE_DEV


def insert_report(table, data, *values):
    data = [data[i:i+VALUE_SIZE] for i in range(0, len(data), VALUE_SIZE)]

    with conn.cursor() as curs:
        formatstr = '({})'.format(','.join(['%s'] * (len(values) + 1)))
        values = b','.join(curs.mogrify(formatstr, (x, *values)) for x in data)
        query = b'INSERT INTO ' + table.encode('utf-8') + b' VALUES ' + values
        try:
            curs.execute(query)
            return curs.statusmessage == 'INSERT 0 {}'.format(len(data))
        except:
            return False


def ip_allowed(ip):
    """ Check if IP address has already sent too many queries """
    ip = ipaddress.ip_address(ip)
    if ip.version == 6:
        # extract /64 prefix
        ip = ipaddress.ip_network((ip, 64), strict=False).network_address
    ip = "{}".format(ip).encode('utf-8')
    ip = hmac.digest(HMAC_SECRET, ip, sha256)[:8]
    query = 'SELECT COUNT(*) FROM siphash WHERE sip = %s'
    with conn.cursor() as curs:
        curs.execute(query, (ip,))
        count = curs.fetchone()[0]
        if count >= MAX_REPORT_PER_IP and not COVITRACE_DEV:
            return False, ip
    return True, ip


@app.route('/v1/report/self', methods=['POST'])
def sreport():
    """
    Self-reported infection case
    """
    # check HTTP body size
    length = request.content_length
    if length < MIN_REPORT_SIZE or length > MAX_REPORT_SIZE:
        return '', 400

    data = request.get_data()
    if not check_pow(data, POW_BITS):
        return '', 400

    # round time to smallest query interval
    stime = int(time.time())
    stime = stime - stime % VALID_INTERVALS[0]
    stime = datetime.utcfromtimestamp(stime)

    # check per IP report limit
    allowed, sip = ip_allowed(get_client_ip())
    if not allowed:
        return '', 403
    else:
        with conn:
            if not insert_sip(sip, stime):
                return '', 403

    # extract per region data with format: size[2] || region[3] || values[...]
    data = data[NONCE_SIZE:]
    regionmap = {}
    try:
        while data:
            regiondata, data = datasize(data)
            # check region format
            region = regiondata[:REGION_SIZE].decode('utf-8')
            if not validregion(region):
                return '', 400
            regionmap[region] = regiondata[REGION_SIZE:]
    except:
        return '', 400

    for region, values in regionmap.items():
            with conn:
                if not insert_report('sreport', values, region, stime):
                    return '', 500

    return '', 200


def insert_rssi(*values):
    query = 'INSERT INTO rssimeasure (value, manuf, model, rssi) VALUES ({})'.format(','.join(len(values) * ['%s']))
    with conn.cursor() as curs:
        try:
            curs.execute(query, values)
            return curs.statusmessage == 'INSERT 0 1'
        except:
            return False


@app.route('/v1/dev/rssi', methods=['POST'])
def rssi():
    """
    User reported measure of RSSI at 1m
    """
    # check HTTP body size
    length = request.content_length
    if length < MIN_RSSI_SIZE or length > MAX_RSSI_SIZE:
        return '', 400

    data = request.get_data()
    if not check_pow(data, POW_BITS):
        return '', 400

    # extract data fields
    value = data[NONCE_SIZE:NONCE_SIZE+VALUE_SIZE]
    try:
        manuf, model, rssi = data[NONCE_SIZE+VALUE_SIZE:].split(b'\0')
        manuf, model, rssi = manuf.decode('utf-8'), model.decode('utf-8'), int(rssi)
    except:
        return '', 400

    with conn:
        if not insert_rssi(value, manuf, model, rssi):
            return '', 500

    return '', 200


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(description='CoviTrace API server',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--debug', help='debug mode', action='store_true', default=False)
    parser.add_argument('-a', '--address', help='listen address', default='127.0.0.1')
    parser.add_argument('-l', '--lport', help='listen port', type=int, default=8000)
    parser.add_argument('-H', '--host', help='database host', default='127.0.0.1')
    parser.add_argument('-p', '--port', help='database port', type=int, default=5432)
    parser.add_argument('-D', '--database', help='database name', default='covitrace')
    parser.add_argument('-U', '--user', help='database user', default='covitrace')
    parser.add_argument('-P', '--password', help='database password', required=True)
    args = parser.parse_args()

    return args


if __name__ == '__main__':
    # command line
    args = parse_args()
    if args.debug:
        COVITRACE_DEV = True
        POW_BITS = 18
    conn = psycopg2.connect(dbname=args.database, host=args.host, port=args.port,
                            user=args.user, password=args.password)
    app.run(host=args.address, port=args.lport, debug=args.debug)
else:
    # gunicorn
    import os
    env = os.environ
    HMAC_SECRET = unhexlify(env['HMAC_SECRET'])
    conn = psycopg2.connect(host=env['DB_HOST'], dbname=env['DB_NAME'], user=env['DB_USER'],
            password=env['DB_PASS'])
    if 'COVITRACE_DEV' in env and env['COVITRACE_DEV'] == '1':
        COVITRACE_DEV = True
        POW_BITS = 18
        app.debug = True
