
require 'mkmf'

# Prefer pkg-config for krb5 and dependencies, fallback to manual checks
if pkg_config('krb5')
  # pkg_config sets cflags/libs for krb5
else
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
  have_library('krb5')
end

pkg_config('com_err') || have_library('com_err')

if pkg_config('kadm5clnt') || have_library('kadm5clnt')
  have_header('kadm5/admin.h')
end

if pkg_config('kdb5') || have_library('kdb5')
  have_header('kdb.h')
else
  raise 'kdb5 library not found'
end

create_makefile('rkerberos')
