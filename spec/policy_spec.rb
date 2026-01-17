# frozen_string_literal: true
require 'spec_helper'
require 'rkerberos'

describe Kerberos::Kadm5::Policy do
  subject(:policy) { described_class.new(name: 'test', max_life: 10000) }

  it 'responds to policy and name' do
    expect(policy).to respond_to(:policy)
    expect(policy).to respond_to(:name)
  end

  it 'name is an alias for policy' do
    expect(policy.method(:name)).to eq(policy.method(:policy))
  end

  it 'requires name to be a string' do
    expect { described_class.new(name: 1) }.to raise_error(TypeError)
  end

  it 'requires name to be present' do
    expect { described_class.new(max_life: 10000) }.to raise_error(ArgumentError)
  end

  it 'responds to min_life' do
    expect(policy).to respond_to(:min_life)
    expect { policy.min_life }.not_to raise_error
  end

  it 'raises if min_life is not a number' do
    expect { described_class.new(name: 'test', min_life: 'test') }.to raise_error(TypeError)
  end

  it 'responds to max_life' do
    expect(policy).to respond_to(:max_life)
    expect { policy.max_life }.not_to raise_error
  end

  it 'raises if max_life is not a number' do
    expect { described_class.new(name: 'test', max_life: 'test') }.to raise_error(TypeError)
  end

  it 'responds to min_length' do
    expect(policy).to respond_to(:min_length)
    expect { policy.min_length }.not_to raise_error
  end
end
