require 'ffi'

module RKerberos
  module Functions
    extend FFI::Library
    ffi_lib 'krb5'

    typedef :int32_t, :krb5_int32
    typedef :krb5_int32, :krb5_error_code

    attach_function :krb5_init_context, [:pointer], :krb5_error_code
    attach_function :krb5_free_context, [:pointer], :void
    attach_function :krb5_get_default_realm, [:pointer, :pointer], :krb5_error_code
    attach_function :krb5_cc_close, [:pointer, :pointer], :krb5_error_code
    attach_function :krb5_cc_default, [:pointer, :pointer], :krb5_error_code
    attach_function :krb5_cc_default_name, [:pointer], :string
    attach_function :krb5_cc_get_principal, [:pointer, :pointer, :pointer], :krb5_error_code
    attach_function :krb5_unparse_name, [:pointer, :pointer, :pointer], :krb5_error_code
    attach_function :krb5_free_principal, [:pointer, :pointer], :void
    attach_function :krb5_free_unparsed_name, [:pointer, :pointer], :void
  end
end
