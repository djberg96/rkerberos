# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'
require 'tmpdir'
require 'fileutils'
require 'pty'
require 'expect'

describe Kerberos::Krb5::Keytab do
  it 'can be constructed with an optional name' do
    expect { described_class.new('FILE:/usr/local/var/keytab') }.not_to raise_error
    expect { described_class.new('FILE:/bogus/keytab') }.not_to raise_error
  end

  it 'raises error for invalid residual type (skipped)' do
    skip('Invalid residual type test skipped for now')
  end
end
