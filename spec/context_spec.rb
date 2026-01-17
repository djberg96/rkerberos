# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'

describe Kerberos::Krb5::Context do
  subject(:context) { described_class.new }

  after { context.close }

  it 'responds to close' do
    expect(context).to respond_to(:close)
  end

  it 'can be closed without error' do
    expect { context.close }.not_to raise_error
  end

  it 'can be closed multiple times without error' do
    expect { 3.times { context.close } }.not_to raise_error
  end
end
