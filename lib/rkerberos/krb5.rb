require_relative 'functions'
require_relative 'structs'

module RKerberos
  class Krb5
    extend FFI::Library
    include RKerberos::Functions
    include RKerberos::Structs

    attr_reader :context

    def initialize
      ptr = FFI::MemoryPointer.new(:pointer)

      rc = krb5_init_context(ptr)
      raise SystemCallError.new("krb5_init_context", rc) if rc != 0

      @context = ptr.read_pointer

      if block_given?
        begin
          yield self
        ensure
          close
        end
      end
    end

    def close
      krb5_free_context(context)
    end

    def default_realm
      ptr = FFI::MemoryPointer.new(:pointer)
      rc = krb5_get_default_realm(context, ptr)

      raise SystemCallError.new("krb5_get_default_realm", rc) if rc != 0

      ptr.read_pointer.read_string
    end


    def default_principal
      cache = FFI::MemoryPointer.new(:pointer)
      rc = krb5_cc_default(context, cache)

      raise SystemCallError.new("krb5_cc_default", rc) if rc != 0

      ccache = cache.read_pointer
      principal_ptr = FFI::MemoryPointer.new(:pointer)
      rc = krb5_cc_get_principal(context, ccache, principal_ptr)

      raise SystemCallError.new("krb5_cc_get_principal", rc) if rc != 0

      principal = RKerberos::Structs::Principal.new(principal_ptr.read_pointer)

    ensure
      krb5_cc_close(context, ccache) if !ccache.null?
    end
  end
end

if $0 == __FILE__
  #krb5 = RKerberos::Krb5.new
  #p krb5.default_realm
  #krb5.close
  RKerberos::Krb5.new do |k|
    p k.default_realm
    p k.default_principal
  end
end
