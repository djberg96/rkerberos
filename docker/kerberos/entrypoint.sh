#!/bin/bash
set -e

/docker-entrypoint-initdb.d/create_principal.sh

/usr/sbin/krb5kdc -n &
/usr/sbin/kadmind -nofork
