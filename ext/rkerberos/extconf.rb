require 'mkmf'

# Default paths set based on 4.x installer for Windows.
if File::ALT_SEPARATOR
  if ['a'].pack('P').length > 4 # 64-bit
    dir_config('rkerberos', 'C:/Progra~1/MIT/Kerberos')
  else
    dir_config('rkerberos', 'C:/Progra~2/MIT/Kerberos')
  end
else
  dir_config('rkerberos', '/usr/local')
end

have_header('krb5.h')

if File::ALT_SEPARATOR
  unless have_library('krb5')
    if ['a'].pack('P').length > 4 # 64-bit
      have_library('amd64/krb5_64')
    else
      have_library('i386/krb5_32')
    end
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

create_makefile('rkerberos')
