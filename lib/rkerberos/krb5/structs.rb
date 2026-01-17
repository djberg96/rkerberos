require 'ffi'

module RKerberos
  module Structs
    extend FFI::Library

    class Context < FFI::Struct
      layout(:context, :pointer)
    end

    class Principal < FFI::Struct
      layout(
        :magic, :int32,
        :realm, :pointer,
        :data, :pointer,
        :length, :int32,
        :type, :int32
      )
    end
  end
end
