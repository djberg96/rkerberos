#!/bin/bash
set -e

# Create the Kerberos database if it doesn't exist
if [ ! -f /var/lib/krb5kdc/principal ]; then
  kdb5_util create -s -P masterpassword
fi

# Add a sample principal and admin
kadmin.local -q "addprinc -pw password testuser@EXAMPLE.COM"
kadmin.local -q "addprinc -pw adminpassword admin/admin@EXAMPLE.COM"
kadmin.local -q "modprinc -kvno 1 testuser@EXAMPLE.COM"
kadmin.local -q "modprinc -kvno 1 admin/admin@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab testuser@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab admin/admin@EXAMPLE.COM"
