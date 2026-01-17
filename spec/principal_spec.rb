# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'

describe Kerberos::Krb5::Principal do
  subject(:princ) { described_class.new('Jon') }

  it 'requires a string argument' do
    expect { described_class.new(1) }.to raise_error(TypeError)
    expect { described_class.new(true) }.to raise_error(TypeError)
  end

  it 'responds to name' do
    expect(princ).to respond_to(:name)
    expect { princ.name }.not_to raise_error
    expect(princ.name).to eq('Jon')
  end

  it 'responds to expire_time' do
    expect(princ).to respond_to(:expire_time)
    expect { princ.expire_time }.not_to raise_error
  end

  it 'responds to last_password_change' do
    expect(princ).to respond_to(:last_password_change)
    expect { princ.last_password_change }.not_to raise_error
  end

  it 'responds to password_expiration' do
    expect(princ).to respond_to(:password_expiration)
    expect { princ.password_expiration }.not_to raise_error
  end

  it 'responds to max_life' do
    expect(princ).to respond_to(:max_life)
    expect { princ.max_life }.not_to raise_error
  end

  it 'responds to mod_name' do
    expect(princ).to respond_to(:mod_name)
    expect { princ.mod_name }.not_to raise_error
  end

  it 'responds to mod_date' do
    expect(princ).to respond_to(:mod_date)
    expect { princ.mod_date }.not_to raise_error
  end
end
