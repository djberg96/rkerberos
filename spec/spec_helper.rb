require 'rspec'
require 'rkerberos'

RSpec.configure do |config|
  config.filter_run_excluding :kadm5 => true unless defined?(Kerberos::Kadm5::Config)
end
