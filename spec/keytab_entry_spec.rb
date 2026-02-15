# spec/keytab_entry_spec.rb
# RSpec tests for Kerberos::Krb5::Keytab::Entry

require 'rkerberos'

RSpec.describe Kerberos::Krb5::Keytab::Entry do
  subject(:kte) { described_class.new }

  describe '#principal' do
    it 'responds to principal' do
      expect(kte).to respond_to(:principal)
    end
    it 'can get principal without error' do
      expect { kte.principal }.not_to raise_error
    end
    it 'can set principal' do
      expect { kte.principal = 'test' }.not_to raise_error
      expect(kte.principal).to eq('test')
    end
  end

  describe '#timestamp' do
    it 'responds to timestamp' do
      expect(kte).to respond_to(:timestamp)
    end
    it 'can get timestamp without error' do
      expect { kte.timestamp }.not_to raise_error
    end
    it 'can set timestamp' do
      time = Time.now
      expect { kte.timestamp = time }.not_to raise_error
      expect(kte.timestamp).to eq(time)
    end
  end

  describe '#vno' do
    it 'responds to vno' do
      expect(kte).to respond_to(:vno)
    end
    it 'can get vno without error' do
      expect { kte.vno }.not_to raise_error
    end
    it 'can set vno' do
      expect { kte.vno = 42 }.not_to raise_error
      expect(kte.vno).to eq(42)
    end
  end

  describe '#key' do
    it 'responds to key' do
      expect(kte).to respond_to(:key)
    end
    it 'can get key without error' do
      expect { kte.key }.not_to raise_error
    end
    it 'can set key' do
      expect { kte.key = 23 }.not_to raise_error
      expect(kte.key).to eq(23)
    end
  end
end
