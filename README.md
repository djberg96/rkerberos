# Description
  The rkerberos library provides a Ruby interface for Kerberos.

# Requirements
  Kerberos 1.7.0 or later, including admin header and library files.

# OS X
  Install krb5 using homebrew:

    `brew install krb5`

  then install this gem using the homebrew version of krb5:

    # Or '/opt/homebrew/opt/krb' depending on your system
    `gem install rkerberos -- --with-rkerberos-dir=/usr/local/opt/krb5`

  or if using bundler:

    `bundle config --global build.rkerberos --with-rkerberos-dir=/usr/local/opt/krb5`
    `bundle install`

# Testing

## Prerequisites
- Ruby 3.4 or later
- Docker or Podman
- docker-compose or podman-compose

## Running Tests with Docker
1. Start the Kerberos and LDAP services:
   ```bash
   docker-compose up -d
   ```

2. Run the test suite:
   ```bash
   docker-compose run --rm rkerberos-test bundle exec rspec
   ```

3. Stop the services when done:
   ```bash
   docker-compose down
   ```

   Add the `--remove-orphans` switch if it's being a pain.

## Running Tests with Podman
1. Start the Kerberos and LDAP services:
   ```bash
   podman-compose up -d
   ```

2. Run the test suite:
   ```bash
   podman-compose run --rm rkerberos-test
   ```

3. Stop the services when done:
   ```bash
   podman-compose down
   ```

## Local Development
If you make changes to the Ruby code or C extensions:

1. Rebuild the test container:
   ```bash
   podman-compose build --no-cache rkerberos-test
   ```

2. Run the tests again:
   ```bash
   podman-compose run --rm rkerberos-test
   ```

The test environment includes:
- MIT Kerberos KDC (Key Distribution Center)
- OpenLDAP server for directory services
- Pre-configured test principals and keytabs

# Notes
  The rkerberos library is a repackaging of my custom branch of the krb5_auth
  library. Eventually the gem djberg96-krb5_auth will be removed from the gem
  index.

# MIT vs Heimdal
  This code was written for the MIT Kerberos library. It has not been tested
  with the Heimdal Kerberos library.

# TODO
* Create a separate class for the replay cache.
* Better credentials cache support.
* Ability to add and delete keytab entries.

# Authors
* Daniel Berger
* Dominic Cleal (maintainer)
* Simon Levermann (maintainer)

# License
  rkerberos is distributed under the Artistic 2.0 license.
