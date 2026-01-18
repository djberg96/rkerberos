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
      skip('Invalid residual type test skipped for now')
    end
  end
end
