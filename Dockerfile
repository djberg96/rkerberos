# Dockerfile for rkerberos Ruby gem testing
FROM ruby:3.2

# Install MIT Kerberos, KDC, admin server, and build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libkrb5-dev krb5-user krb5-kdc krb5-admin-server rake build-essential && \
    rm -rf /var/lib/apt/lists/*

# Set up a working directory
WORKDIR /app

# Copy the gemspec and Gemfile for dependency installation
COPY Gemfile rkerberos.gemspec ./


# Install gem dependencies and RSpec
RUN bundle install && gem install rspec


# Create a more complete krb5.conf for testing (with kadmin support)
RUN echo "[libdefaults]\n  default_realm = EXAMPLE.COM\n  dns_lookup_realm = false\n  dns_lookup_kdc = false\n  ticket_lifetime = 24h\n  renew_lifetime = 7d\n  forwardable = true\n[realms]\n  EXAMPLE.COM = {\n    kdc = localhost\n    admin_server = localhost\n    default_domain = example.com\n  }\n[domain_realm]\n  .example.com = EXAMPLE.COM\n  example.com = EXAMPLE.COM\n[kadmin]\n  default_keys = des-cbc-crc:normal des-cbc-md5:normal aes256-cts:normal aes128-cts:normal rc4-hmac:normal\n  admin_server = localhost\n" > /etc/krb5.conf


# Create a minimal KDC and admin server config, and a permissive ACL for kadmin
RUN mkdir -p /etc/krb5kdc && \
    echo "[kdcdefaults]\n kdc_ports = 88\n[kdc]\n profile = /etc/krb5.conf\n" > /etc/krb5kdc/kdc.conf && \
    echo "admin/admin@EXAMPLE.COM *" > /etc/krb5kdc/kadm5.acl


# Create a KDC database and stash file if not present, then add principals
RUN if [ ! -f /var/lib/krb5kdc/principal ]; then \
        yes | krb5_newrealm; \
    fi && \
    kadmin.local -q "addprinc -pw adminpassword admin/admin@EXAMPLE.COM" && \
    kadmin.local -q "addprinc -pw testpassword testuser@EXAMPLE.COM" && \
    kadmin.local -q "addprinc -randkey host/localhost@EXAMPLE.COM"

# Copy the rest of the code
COPY . .

# Start KDC and admin server in the background, wait for readiness, run RSpec, then keep container alive
CMD bash -c "/usr/sbin/krb5kdc & /usr/sbin/kadmind & for i in \$(seq 1 10); do echo 'Waiting for KDC...'; kadmin.local -q 'listprincs' && break; sleep 1; done; rspec --format documentation || true; fg || true"
