# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'

describe Kerberos::Krb5::Keytab::Entry do
  subject(:kte) { described_class.new }

  it 'responds to principal' do
    expect(kte).to respond_to(:principal)
    expect { kte.principal }.not_to raise_error
  end

  it 'allows setting principal' do
    expect { kte.principal = 'test' }.not_to raise_error
    expect(kte.principal).to eq('test')
  end

  it 'responds to timestamp' do
    expect(kte).to respond_to(:timestamp)
    expect { kte.timestamp }.not_to raise_error
  end

  it 'allows setting timestamp' do
    time = Time.now
    expect { kte.timestamp = time }.not_to raise_error
    expect(kte.timestamp).to eq(time)
  end

  it 'responds to vno' do
    expect(kte).to respond_to(:vno)
    expect { kte.vno }.not_to raise_error
  end

  it 'allows setting vno' do
    expect { kte.vno = 42 }.not_to raise_error
    expect(kte.vno).to eq(42)
  end

  it 'responds to key' do
    expect(kte).to respond_to(:key)
    expect { kte.key }.not_to raise_error
  end

  it 'allows setting key' do
    expect { kte.key = 23 }.not_to raise_error
    expect(kte.key).to eq(23)
  end
end
