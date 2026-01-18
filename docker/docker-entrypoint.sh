#!/bin/bash
set -e

# Initialize KDC DB if not already present
if [ ! -f /etc/krb5kdc/.k5.EXAMPLE.COM ]; then
  printf "masterpassword\nmasterpassword\n" | krb5_newrealm
  kadmin.local -q "addprinc -pw adminpassword admin/admin"
fi

# Create standard test principals for keytab/credential cache tests
kadmin.local -q "addprinc -pw changeme testuser1@EXAMPLE.COM"
kadmin.local -q "addprinc -pw changeme zztop@EXAMPLE.COM"
kadmin.local -q "addprinc -pw changeme martymcfly@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab testuser1@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab zztop@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab martymcfly@EXAMPLE.COM"

# Start KDC and admin server
krb5kdc
kadmind

# Keep container running
trap : TERM INT; sleep infinity & wait
