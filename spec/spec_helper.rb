require 'rkerberos'
require 'rspec'

RSpec.configure do |config|
  config.filter_run_excluding :kadm5 => true unless defined?(Kerberos::Kadm5::Config)
  config.filter_run_excluding :unix => true if File::ALT_SEPARATOR

  krb5_conf = ENV['KRB5_CONFIG']
  krb5_cc_name = ENV['KRB5CCNAME']

  if File::ALT_SEPARATOR
    krb5_conf ||= 'C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini'
    krb5_cc_name ||= File.join(Dir.home, 'krb5cache')
  else
    krb5_conf ||= '/etc/krb5.conf'
  end

  config.add_setting :krb5_conf
  config.krb5_conf = krb5_conf

  config.add_setting :krb5_cc_name
  config.krb5_cc_name = krb5_cc_name

  unless File.exist?(krb5_conf)
    config.filter_run_excluding :krb5_config => true
  end
end
