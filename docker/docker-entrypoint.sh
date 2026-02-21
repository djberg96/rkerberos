#!/bin/bash
set -e

# Initialize KDC DB if not already present
if [ ! -f /etc/krb5kdc/.k5.EXAMPLE.COM ]; then
  printf "masterpassword\nmasterpassword\n" | krb5_newrealm
  kadmin.local -q "addprinc -pw adminpassword admin/admin"
fi

# Create or update standard test principals for keytab/credential cache tests.
# Use addprinc when principal is missing; otherwise enforce the known password with cpw.
for p in testuser1 zztop martymcfly; do
  kadmin.local -q "addprinc -pw changeme ${p}@EXAMPLE.COM" 2>/dev/null || \
    kadmin.local -q "cpw -pw changeme ${p}@EXAMPLE.COM"

  # Attempt to add keys to the system keytab; ignore errors caused by volume mounts.
  kadmin.local -q "ktadd -k /etc/krb5.keytab ${p}@EXAMPLE.COM" 2>/dev/null || true
done

# Start KDC and admin server
krb5kdc
kadmind

# Keep container running
trap : TERM INT; sleep infinity & wait
