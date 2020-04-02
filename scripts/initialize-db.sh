#!/usr/bin/env bash

fatal() {
    echo "$@" >&2
    exit 1
}

[ -n "$POSTGRES_PASSWORD" ] || fatal "Please define postgres pass in POSTGRES_PASSWORD env"
[ -n "$COVITRACE_PASSWORD" ] || fatal "Please define covitrace pass in COVITRACE_PASSWORD env"

cd "$(dirname "$0")/.."

postgresip="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' postgresql)"
[ -n "$postgresip" ] || fatal "Failed to get IP from postgresql container"

export PGHOST="$postgresip"
export PGUSER='postgres'
export PGPASSWORD="$POSTGRES_PASSWORD"

psql -c "CREATE USER covitrace with PASSWORD '$COVITRACE_PASSWORD';"
psql -c "CREATE DATABASE covitrace OWNER covitrace;"

export PGUSER='covitrace'
export PGPASSWORD="$COVITRACE_PASSWORD"

psql covitrace < data/covitrace.sql
