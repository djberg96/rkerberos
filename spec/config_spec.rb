# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'

describe Kerberos::Kadm5::Config do
  subject(:config) { described_class.new }

  it 'is frozen' do
    expect(config.frozen?).to be true
  end

  it 'returns a realm as a string' do
    expect(config.realm).to be_a(String)
  end

  it 'returns a kadmind_port as a Fixnum' do
    expect(config.kadmind_port).to be_a(Integer)
  end

  it 'returns a kpasswd_port as a Fixnum' do
    expect(config.kpasswd_port).to be_a(Integer)
  end

  it 'returns an admin_server as a string' do
    expect(config.admin_server).to be_a(String)
  end

  it 'returns an acl_file as a string' do
    expect(config.acl_file).to be_a(String)
  end

  it 'returns a dict_file as a string or nil' do
    expect([String, NilClass]).to include(config.dict_file.class)
  end

  it 'returns a stash_file as a string or nil' do
    expect([String, NilClass]).to include(config.stash_file.class)
  end

  it 'returns a mkey_name as a string or nil' do
    expect([String, NilClass]).to include(config.mkey_name.class)
  end
end
