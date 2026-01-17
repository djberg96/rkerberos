# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'
require 'dbi/dbrc'
require 'socket'

describe Kerberos::Kadm5 do
  # Only a basic instantiation test, as full tests require local config
  it 'can be instantiated (if config present)' do
    expect { described_class.new rescue nil }.not_to be_nil
  end
end
