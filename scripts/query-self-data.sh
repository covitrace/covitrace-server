#!/usr/bin/env bash

URL='http://127.0.0.1/v1/data/self'
URL='http://127.0.0.1:8000/v1/data/self'
INTERVAL=10800

now="$(date '+%s')"
now=$(( now - now % $INTERVAL ))

curl -s "${URL}/2w4/${INTERVAL}/${now}"
