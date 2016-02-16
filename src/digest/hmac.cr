require "../openssl"
require "./digest_base"

class OpenSSL::HMAC
  class HMACError < OpenSSLError; end

  include DigestBase

  def initialize
    @ctx = LibCrypto::HMAC_CTX_Struct.new
    LibCrypto.hmac_ctx_init(self)
  end

  def finalize
    LibCrypto.hmac_ctx_cleanup(self)
  end

  def self.new(key, digest)
    new.tap do |hmac|
      LibCrypto.hmac_init_ex(hmac, key.to_unsafe as Pointer(Void), key.bytesize, digest.to_unsafe_md, nil)
    end
  end

  def clone
    HMAC.new.tap do |hmac|
      LibCrypto.hmac_ctx_copy(hmac, self)
    end
  end

  def reset
    LibCrypto.hmac_init(self, nil, 0, nil)
    self
  end

  def update(data)
    LibCrypto.hmac_update(self, data, LibC::SizeT.new(data.bytesize))
    self
  end

  protected def finish
    size = LibCrypto.evp_md_size(@ctx.md)
    data = Slice(UInt8).new(size)
    LibCrypto.hmac_final(self, data, out len)
    data[0, len.to_i32]
  end

  def to_unsafe
    pointerof(@ctx)
  end
end
