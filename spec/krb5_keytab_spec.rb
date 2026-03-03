# spec/krb5_keytab_spec.rb
# RSpec tests for Kerberos::Krb5::Keytab

require 'rkerberos'
require 'tmpdir'
require 'fileutils'
require 'pty'
require 'expect'



RSpec.describe Kerberos::Krb5::Keytab do
  before(:all) do
    @realm = Kerberos::Kadm5::Config.new.realm
    @keytab_file = File.join(Dir.tmpdir, 'test.keytab')
    @keytab_name = "FILE:#{@keytab_file}"
    PTY.spawn('ktutil') do |reader, writer, _|
      reader.expect(/ktutil:\s+/)
      writer.puts("add_entry -password -p testuser1@#{@realm} -k 1 -e aes128-cts-hmac-sha1-96")
      reader.expect(/Password for testuser1@#{Regexp.quote(@realm)}:\s+/)
      writer.puts('asdfasdfasdf')
      reader.expect(/ktutil:\s+/)
      writer.puts("add_entry -password -p testuser2@#{@realm} -k 1 -e aes128-cts-hmac-sha1-96")
      reader.expect(/Password for testuser2@#{Regexp.quote(@realm)}:\s+/)
      writer.puts('asdfasdfasdf')
      reader.expect(/ktutil:\s+/)
      writer.puts("wkt #{@keytab_file}")
      reader.expect(/ktutil:\s+/)
    end
  end

  subject(:keytab) { described_class.new }

  describe 'constructor' do
    it 'accepts an optional name' do
      expect { described_class.new("FILE:/usr/local/var/keytab") }.not_to raise_error
      expect { described_class.new("FILE:/bogus/keytab") }.not_to raise_error
    end

    it 'raises error for invalid residual type' do
      expect {
        described_class.new("BOGUS:/tmp/keytab")
      }.to raise_error(Kerberos::Krb5::Keytab::Exception)
    end
  end

  describe '#keytab_name and #keytab_type' do
    it 'returns the underlying name and type strings' do
      kt = described_class.new(@keytab_name)
      expect(kt).to respond_to(:keytab_name)
      expect(kt).to respond_to(:keytab_type)

      expect(kt.keytab_name).to be_a(String)
      expect(kt.keytab_type).to be_a(String)

      # name should include the residual portion we supplied
      expect(kt.keytab_name).to include(File.basename(@keytab_file))
      # type should match the scheme
      expect(kt.keytab_type.downcase).to eq("file")
    end
  end

  describe '#dup' do
    it 'creates an independent handle referring to same keytab' do
      kt1 = described_class.new(@keytab_name)
      kt2 = kt1.dup
      expect(kt2).to be_a(described_class)
      expect(kt2.keytab_name).to eq(kt1.keytab_name)

      # closing one should not invalidate the other
      kt1.close
      expect { kt2.keytab_name }.not_to raise_error
    end

    it 'clone is an alias for dup' do
      kt = described_class.new(@keytab_name)
      expect(kt.method(:clone)).to eq(kt.method(:dup))
    end
  end
end
