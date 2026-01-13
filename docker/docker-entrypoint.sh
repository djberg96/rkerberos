#!/bin/bash
set -e



# LDAP/Kerberos schema and container automation
ldap_container_dn="cn=krbcontainer,dc=example,dc=com"
ldap_admin_dn="cn=admin,dc=example,dc=com"
ldap_admin_pw="admin"
krb_schema_file="/tmp/kerberos.ldif"

# Wait for LDAP to be up
until ldapsearch -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" -b "dc=example,dc=com" > /dev/null 2>&1; do
  echo "Waiting for LDAP..."
  sleep 2
done

# Load Kerberos LDAP schema if not present
if ! ldapsearch -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" -b "cn=schema,cn=config" | grep -q "krbPrincipalAux"; then
  echo "Loading Kerberos LDAP schema..."
  cat > "$krb_schema_file" <<EOF
dn: cn=kerberos,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: kerberos
olcAttributeTypes: ( 1.3.6.1.4.1.5322.17.1.1 NAME 'krbPrincipalName' DESC 'Kerberos principal name' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.5322.17.1.2 NAME 'krbPrincipalRealm' DESC 'Kerberos principal realm' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.5322.17.2.1 NAME 'krbPrincipalAux' DESC 'Kerberos principal auxiliary object class' AUXILIARY MAY ( krbPrincipalName $ krbPrincipalRealm ) )
olcObjectClasses: ( 1.3.6.1.4.1.5322.17.2.2 NAME 'krbContainer' DESC 'Kerberos container object class' STRUCTURAL MUST cn )
EOF
  ldapadd -Y EXTERNAL -H ldapi:/// -f "$krb_schema_file" || true
fi

# Create Kerberos container if missing
if ! ldapsearch -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" -b "$ldap_container_dn" | grep -q "$ldap_container_dn"; then
  echo "Creating Kerberos LDAP container..."
  ldapadd -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" <<EOF
dn: cn=krbcontainer,dc=example,dc=com
objectClass: top
objectClass: krbContainer
cn: krbcontainer
EOF
fi

# Seed LDAP with required user for dn=... principal creation
if ! ldapsearch -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" -b "ou=People,dc=example,dc=com" | grep -q "ou=People"; then
  echo "Adding LDAP subtree: ou=People,dc=example,dc=com"
  ldapadd -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" <<EOF
dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
EOF
fi
if ! ldapsearch -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" -b "uid=existingldap,ou=People,dc=example,dc=com" | grep -q "uid=existingldap"; then
  echo "Adding LDAP user: existingldap"
  ldapadd -x -H ldap://ldap:389 -D "$ldap_admin_dn" -w "$ldap_admin_pw" <<EOF
dn: uid=existingldap,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
uid: existingldap
sn: Existing
givenName: LDAP
cn: Existing LDAP
displayName: Existing LDAP
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/existingldap
loginShell: /bin/bash
mail: existingldap@example.com
userPassword: changeme
EOF
fi

# Initialize KDC DB in LDAP if not already present
if [ ! -f /etc/krb5kdc/.k5.EXAMPLE.COM ]; then
  kdb5_ldap_util -D "$ldap_admin_dn" -w "$ldap_admin_pw" create -subtrees "dc=example,dc=com" -r EXAMPLE.COM -s
  kadmin.local -q "addprinc -pw adminpassword admin/admin"
fi

# Ensure all test principals exist and are in the keytab (LDAP-backed)

# Create LDAP test principal under expected subtree
kadmin.local -q "addprinc -x containerdn=cn=krbcontainer,dc=example,dc=com -pw changeme ldaptestuser@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab ldaptestuser@EXAMPLE.COM"

# Create principal for existing LDAP user with dn db_princ_args
kadmin.local -q "addprinc -x dn=uid=existingldap,ou=People,dc=example,dc=com -pw changeme existingldap@EXAMPLE.COM"
kadmin.local -q "ktadd -k /etc/krb5.keytab existingldap@EXAMPLE.COM"

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
