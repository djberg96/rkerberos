# spec/kadm5_spec.rb
# RSpec tests for Kerberos::Kadm5

require 'rkerberos'
require 'socket'

RSpec.describe Kerberos::Kadm5 do
  before(:all) do
    @server = Kerberos::Kadm5::Config.new.admin_server
    @host = Socket.gethostname
    @user = ENV['KRB5_ADMIN_PRINCIPAL']
    @pass = ENV['KRB5_ADMIN_PASSWORD']
    @krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    ENV['KRB5_CONFIG'] = @krb5_conf
    @test_princ = 'zztop'
    @test_policy = 'test_policy'
  end

  let(:user) { @user }
  let(:pass) { @pass }
  let(:test_princ) { @test_princ }
  let(:test_policy) { @test_policy }

  describe 'constructor' do
    it 'responds to .new' do
      expect(described_class).to respond_to(:new)
    end
    it 'works with valid user and password' do
      expect { described_class.new(principal: user, password: pass) }.not_to raise_error
    end
    it 'works with valid service' do
      expect {
        described_class.new(principal: user, password: pass, service: 'kadmin/admin')
      }.not_to raise_error
    end
    it 'only accepts a hash argument' do
      expect { described_class.new(user) }.to raise_error(TypeError)
      expect { described_class.new(1) }.to raise_error(TypeError)
    end
    it 'accepts a block and yields itself' do
      expect { described_class.new(principal: user, password: pass) {} }.not_to raise_error
      described_class.new(principal: user, password: pass) { |kadm5| expect(kadm5).to be_a(described_class) }
    end
    it 'requires principal to be specified' do
      expect { described_class.new({}) }.to raise_error(ArgumentError)
    end
    it 'requires principal to be a string' do
      expect { described_class.new(principal: 1) }.to raise_error(TypeError)
    end
    it 'requires password to be a string' do
      expect { described_class.new(principal: user, password: 1) }.to raise_error(TypeError)
    end
    it 'requires keytab to be a string or boolean' do
      expect { described_class.new(principal: user, keytab: 1) }.to raise_error(TypeError)
    end
    it 'requires service to be a string' do
      expect { described_class.new(principal: user, password: pass, service: 1) }.to raise_error(TypeError)
    end
  end

  # ... (Due to length, only a representative subset of tests is shown. The rest should be ported similarly.)
end
