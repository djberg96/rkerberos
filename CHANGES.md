# 0.2.2 - 3-Mar-2026
* Added custom .dup methods for CredentialsCache and Keytab.
* Added the keytab_name and keytab_type methods to Keytab.
* Added the cache_name, cache_type and principal methods to CredentialsCache.
* The Keytab#get_entry method now properly honors the vno and encoding type arguments.
* Fixed the max_life and max_rlife attributes in Config.
* Fixed the get_privileges method in Kadm5.
* Fixed the change_password method in Kadm5 and added specs for it. Previously it would
  generally always return true because it wasn't considering KDC failures, only raw
  function failures.
* Heaps of memory leak fixes. Get it? Heaps? Right, I'll see myself out.
* Converted the CHANGES and MANIFEST files to markdown.

# 0.2.1 - 1-Mar-2026
* Added the verify_init_creds and an authenticate! methods.
* The Context constructor now accepts optional :secure and/or :profile arguments
  for different types of contexts.
* Minor fix for the CredentialsCache constructor.
* Minor fix for the get_init_creds_keytab method.
* Fixed a mistake in an rb_funcall in the Policy class (thanks Ondřej Gajdušek).
* Update gemspec so that releases don't include Docker related files (thanks Ondřej Gajdušek).
* Add a spec:compose task for convenience.
* The rake-compiler gem is now a development dependency, not a runtime
  dependency (thanks Ondřej Gajdušek).

# 0.2.0 - 14-Feb-2026
* Added Docker and Podman support for running tests in isolated environments with Kerberos and OpenLDAP services.
* Updated documentation with modern testing and development workflows, including container-based instructions.
* Improved compatibility for Ruby 3.4 and later.
* Enhanced build and test automation using docker-compose and podman-compose.
* Various bug fixes, code cleanups, and test improvements.

# 0.1.5 - 17-Oct-2016
* Fix build error on Ruby 2.0.0/2.1 with CFLAGS concatenation

# 0.1.4 - 14-Oct-2016
* Implement db_args functionality in kadmin (fixes #8)
* Fix a double-free error when setting the realm for a principal
* Fix an error in policy creation that would sometimes cause a communication failure
* Set C99 as the C Standard and fix all compiler warnings at this level

# 0.1.3 - 07-Sep-2013
* Add optional 'service' argument to get_init_creds_password (fixes #3)
* Artistic License 2.0 text now included (fixes #2)

# 0.1.2 - 24-Jun-2013
* Fix kadm5clnt build issue on EL6
* Remove admin_keytab references for krb5 1.11
* Add Gemfile
* Replace deprecated Config with RbConfig (Ruby 2)

# 0.1.1 - 08-May-2013
* Add credential cache argument to get_init_creds_keytab
* Fixed invalid VALUE declarations affecting non-gcc compilers
* Add OS X install instructions

# 0.1.0 - 28-Apr-2011
* Initial release. This is effectively a re-release of my own custom branch
  of the krb5-auth library, with some minor changes.
