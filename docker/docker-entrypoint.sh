#!/bin/bash
set -e

# Reset KDC database on every start for predictable test state
rm -f /etc/krb5kdc/.k5.EXAMPLE.COM
printf "masterpassword\nmasterpassword\n" | krb5_newrealm
kadmin.local -q "addprinc -pw adminpassword admin/admin"

# Start KDC and admin server in background, then wait for them
krb5kdc &
kadmind &

for i in {1..20}; do
  echo "waiting for kadmin.local... ($i)"
  if kadmin.local -q "listprincs" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Create or update standard test principals for keytab/credential cache tests.
# Use addprinc when principal is missing; otherwise enforce the known password with cpw.
for p in testuser1 zztop martymcfly; do
  # create principal if missing; ignore failure if already exists
  kadmin.local -q "addprinc -pw changeme ${p}@EXAMPLE.COM" 2>/dev/null || true

  # enforce known password unconditionally (cpw will succeed in either case)
  kadmin.local -q "cpw -pw changeme ${p}@EXAMPLE.COM"

  # Attempt to add keys to the system keytab; ignore errors caused by volume mounts.
  kadmin.local -q "ktadd -k /etc/krb5.keytab ${p}@EXAMPLE.COM" 2>/dev/null || true
done

# Ensure container stays alive until explicitly stopped
trap : TERM INT; sleep infinity & wait
