# spec/krb5_spec.rb
# RSpec tests for Kerberos::Krb5

require 'rkerberos'
require 'open3'

RSpec.describe Kerberos::Krb5 do
  before(:all) do
    @cache_found = true
    Open3.popen3('klist') { |_, _, stderr| @cache_found = false unless stderr.gets.nil? }
    @krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    @realm = IO.read(@krb5_conf).split("\n").grep(/default_realm/).first.split('=').last.lstrip.chomp
  end

  subject(:krb5) { described_class.new }
  let(:keytab) { Kerberos::Krb5::Keytab.new.default_name.split(':').last }
  let(:user) { "testuser1@#{@realm}" }
  let(:service) { 'kadmin/admin' }

  it 'has the correct version constant' do
    expect(Kerberos::Krb5::VERSION).to eq('0.2.0')
  end

  it 'accepts a block and yields itself' do
    expect { described_class.new {} }.not_to raise_error
    described_class.new { |k| expect(k).to be_a(described_class) }
  end

  describe '#get_default_realm' do
    it 'responds to get_default_realm' do
      expect(krb5).to respond_to(:get_default_realm)
    end
    it 'can be called without error' do
      expect { krb5.get_default_realm }.not_to raise_error
      expect(krb5.get_default_realm).to be_a(String)
    end
    it 'takes no arguments' do
      expect { krb5.get_default_realm('localhost') }.to raise_error(ArgumentError)
    end
    it 'matches the realm from krb5.conf' do
      expect(krb5.get_default_realm).to eq(@realm)
    end
    it 'default_realm is an alias for get_default_realm' do
      expect(krb5.method(:default_realm)).to eq(krb5.method(:get_default_realm))
    end
  end

  describe '#verify_init_creds' do
    it 'responds to verify_init_creds' do
      expect(krb5).to respond_to(:verify_init_creds)
    end

    it 'raises when no credentials have been acquired' do
      expect { krb5.verify_init_creds }.to raise_error(Kerberos::Krb5::Exception)
    end

    it 'validates argument types' do
      expect { krb5.verify_init_creds(true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(nil, true) }.to raise_error(TypeError)
      expect { krb5.verify_init_creds(nil, nil, true) }.to raise_error(TypeError)
    end
  end
end
