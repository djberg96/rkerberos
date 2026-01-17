FROM debian:stable-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y krb5-kdc krb5-admin-server krb5-user && \
    rm -rf /var/lib/apt/lists/*

ENV KRB5_REALM=EXAMPLE.COM
ENV KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf
ENV KRB5_KDC_ACL=/etc/krb5kdc/kadm5.acl
ENV KRB5_KDC_DB=/var/lib/krb5kdc/principal

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY kadm5.acl /etc/krb5kdc/kadm5.acl
COPY create_principal.sh /docker-entrypoint-initdb.d/create_principal.sh

RUN mkdir -p /var/lib/krb5kdc && chmod 700 /var/lib/krb5kdc
RUN chmod +x /docker-entrypoint-initdb.d/create_principal.sh

EXPOSE 88 749

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
