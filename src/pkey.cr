require "./openssl"

module OpenSSL
  abstract class PKey
    class PKeyError < OpenSSLError; end

    def initialize(@pkey: LibCrypto::EVP_PKEY, @is_private = false)
      raise PKeyError.new "Invalid EVP_PKEY" unless @pkey
    end

    def initialize(is_private)
      initialize(LibCrypto.evp_pkey_new(), is_private)
    end

    def to_unsafe
      @pkey
    end

    def finalize
      LibCrypto.evp_pkey_free(self)
    end

    def private_key?
      @is_private
    end

    def public_key?
      true
    end

    def sign(digest, data)
      unless private_key?
        raise PKeyError.new "Private key is needed"
      end
      data = data.to_slice
      LibCrypto.evp_digestinit_ex(digest, digest.to_unsafe_md, nil)
      LibCrypto.evp_digestupdate(digest, data, LibC::SizeT.cast(data.length))
      size = LibCrypto.evp_pkey_size(self)
      slice = Slice(UInt8).new(size)
      if LibCrypto.evp_signfinal(digest, slice, out len, self) == 0
        raise PKeyError.new "Unable to sign"
      end
      slice[0, len.to_i32]
    end

    def verify(digest, signature, data)
      data = data.to_slice
      signature = signature.to_slice
      LibCrypto.evp_digestinit_ex(digest, digest.to_unsafe_md, nil)
      LibCrypto.evp_digestupdate(digest, data, LibC::SizeT.cast(data.length))
      case LibCrypto.evp_verifyfinal(digest, signature, signature.length.to_u32, self)
      when 0
        false
      when 1
        true
      else
        raise PKeyError.new "Unable to verify"
      end
    end
  end

  class PKey::RSA < PKey
    class RSAError < PKeyError; end

    def self.new(io: IO | String, password = nil)
      bio = BIO.new
      io = StringIO.new(io) if io.is_a?(String)
      IO.copy(io, bio)
      # FIXME: password callback
      new(LibCrypto.pem_read_bio_privatekey(bio, nil, nil, nil), true)
    end

    def self.generate(size)
      rsa = LibCrypto.rsa_generate_key(size, 65537.to_u32, nil, nil)
      new(true).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::NID_rsaEncryption, rsa as Pointer(Void))
      end
    end

    def public_key
      pub_rsa = LibCrypto.rsapublickey_dup(rsa)
      RSA.new(false).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::NID_rsaEncryption, pub_rsa as Pointer(Void))
      end
    end

    private def max_encrypt_size
      LibCrypto.rsa_size(rsa)
    end

    private def rsa
      LibCrypto.evp_pkey_get1_rsa(self)
    end

    def public_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      if max_encrypt_size < from.length
        raise RSAError.new "value is too big to be encrypted"
      end
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_encrypt(from.length, from, to, rsa, padding)
      if len < 0
        raise RSAError.new "unable to encrypt"
      end
      to[0, len]
    end

    def public_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_public_decrypt(from.length, from, to, rsa, padding)
      if len < 0
        raise RSAError.new "unable to decrypt"
      end
      to[0, len]
    end

    def private_encrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      unless private_key?
        raise RSAError.new "private key needed"
      end
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_encrypt(from.length, from, to, rsa, padding)
      if len < 0
        raise RSAError.new "unable to encrypt"
      end
      to[0, len]
    end

    def private_decrypt(data, padding = LibCrypto::Padding::PKCS1_PADDING)
      unless private_key?
        raise RSAError.new "private key needed"
      end
      from = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      len = LibCrypto.rsa_private_decrypt(from.length, from, to, rsa, padding)
      if len < 0
        raise RSAError.new "unable to decrypt"
      end
      to[0, len]
    end

    def to_pem(io)
      bio = BIO.new
      if private_key?
        LibCrypto.pem_write_bio_rsaprivatekey(bio, rsa, nil, nil, 0, nil, nil)
      else
        LibCrypto.pem_write_bio_rsa_pubkey(bio, rsa)
      end
      IO.copy(bio, io)
    end

    def to_pem
      io = StringIO.new
      to_pem(io)
      io.to_s
    end

    def to_text
      bio = BIO.new
      LibCrypto.rsa_print(bio, rsa, 0)
      bio.to_string
    end

    def to_der
      fn = ->(buf: UInt8**|Nil) {
        if private_key?
          LibCrypto.i2d_rsaprivatekey(rsa, buf)
        else
          LibCrypto.i2d_rsa_pubkey(rsa, buf)
        end
      }
      len = fn.call(nil)
      if len <= 0
        raise RSAError.new
      end
      slice = Slice(UInt8).new(len)
      p = slice.to_unsafe
      len = fn.call(pointerof(p))
      slice[0, len]
    end
  end
end
