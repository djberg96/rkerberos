# spec/context_spec.rb
# RSpec tests for Kerberos::Krb5::Context

require 'rkerberos'

RSpec.describe Kerberos::Krb5::Context do
  subject(:context) { described_class.new }

  describe '#close' do
    it 'responds to close' do
      expect(context).to respond_to(:close)
    end
    it 'can be called without error' do
      expect { context.close }.not_to raise_error
    end
    it 'can be called multiple times without error' do
      expect { 3.times { context.close } }.not_to raise_error
    end
  end

  after(:each) do
    context.close
  end
end
