CoviTrace API server
====================

Flask based API server for the **CoviTrace** project.


Setup dev environment
---------------------
```
export POSTGRES_PASSWORD=PostgresDevPassword
export COVITRACE_PASSWORD=CoviTraceDevPassword
export HMAC_SECRET=b0dad480ea194f99e5846ca157520d02
sudo -E docker-compose -f docker-compose.dev.yml up -d
./scripts/initialize-db.sh
```


Setup prod environment
----------------------

Generate SSL key and corresponding CSR.

```
SUBJCN='api.covitrace.org'
openssl genpkey -algorithm RSA -out data/ssldata/privkey.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -sha256 -key data/ssldata/privkey.pem -subj "/CN=${SUBJCN}" -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:${SUBJCN}")) \
    > data/ssldata/csr.pem
```

Get CSR signed by CA and place certificate in `data/ssldata/certificate.pem`.

Start API server with nginx reverse proxy.

```
export POSTGRES_PASSWORD=XXX
export COVITRACE_PASSWORD=XXX
export HMAC_SECRET=XXX
sudo -E docker-compose -f docker-compose.prod.yml up -d
./scripts/initialize-db.sh
```
