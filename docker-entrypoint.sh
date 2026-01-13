#!/bin/bash
set -e

# Initialize KDC DB if not already present
if [ ! -f /var/lib/krb5kdc/principal ]; then
  kdb5_util create -s -P masterkey
  kadmin.local -q "addprinc -pw adminpassword admin/admin"
fi

# Start KDC and admin server
krb5kdc
kadmind

# Keep container running
trap : TERM INT; sleep infinity & wait