require 'mkmf'

if File::ALT_SEPARATOR
  dir_config('rkerberos', 'C:/Progra~2/MIT/Kerberos')
else
  dir_config('rkerberos', '/usr/local')
end

have_header('krb5.h')

if File::ALT_SEPARATOR
  unless have_library('krb5')
    have_library('i386/krb5_32')
  end
else
  have_library('krb5')
end

unless pkg_config('com_err')
  puts 'warning: com_err not found, usually a dependency for kadm5clnt'
end

if have_header('kadm5/admin.h')
  have_library('kadm5clnt')
end

if have_header('kdb.h')
  have_library('libkdb5')
else
  raise 'kdb5 library not found'
end

$CFLAGS << ' -std=c99 -Wall -pedantic'
create_makefile('rkerberos')
