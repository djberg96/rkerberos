# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'
require 'open3'

describe Kerberos::Krb5 do
  subject(:krb5) { described_class.new }

  it 'has a VERSION constant' do
    expect(Kerberos::Krb5::VERSION).to eq('0.1.0')
  end

  it 'yields itself if given a block' do
    expect { |b| described_class.new(&b) }.to yield_with_args(described_class)
  end

  it 'returns a default realm as a string' do
    expect(krb5.get_default_realm).to be_a(String)
  end

  it 'raises ArgumentError if get_default_realm gets arguments' do
    expect { krb5.get_default_realm('localhost') }.to raise_error(ArgumentError)
  end

  it 'default_realm is an alias for get_default_realm' do
    expect(krb5.method(:default_realm)).to eq(krb5.method(:get_default_realm))
  end
end
