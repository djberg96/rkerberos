# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'
require 'etc'
require 'tmpdir'
require 'open3'

describe Kerberos::Krb5::CredentialsCache do
  let(:login) { Etc.getlogin }
  let(:princ) { login + '@' + Kerberos::Krb5.new.default_realm }
  let(:cfile) { File.join(Dir.tmpdir, 'krb5cc_' + Etc.getpwnam(login).uid.to_s) }

  def cache_found?
    found = true
    Open3.popen3('klist') { |_stdin, _stdout, stderr| found = false unless stderr.gets.nil? }
    found
  end

  after { File.delete(cfile) if File.exist?(cfile) }

  it 'can be constructed with no arguments' do
    expect { described_class.new }.not_to raise_error
  end

  it 'does not create a cache with no arguments' do
    described_class.new
    expect(File.exist?(cfile)).to be false
    expect(cache_found?).to be false
  end

  it 'creates a credentials cache with a principal' do
    described_class.new(princ)
    expect(File.exist?(cfile)).to be true
    expect(cache_found?).to be true
  end

  it 'accepts an explicit cache name' do
    expect { described_class.new(princ, cfile) }.not_to raise_error
    expect { described_class.new(nil, cfile) }.not_to raise_error
  end

  it 'raises error for non-string argument' do
    expect { described_class.new(true) }.to raise_error(TypeError)
  end
end
