require "./src/lib/lib_ssl"
# require "secure_random"

LibSSL.ssl_library_init
LibSSL.openssl_add_all_algorithms
LibSSL.err_load_crypto_strings
LibSSL.ssl_load_error_strings

class Cipher
  class Error < Exception
  end

  def initialize(name = "aes-128-cbc")
    cipher = LibCrypto.evp_get_cipherbyname name
    raise ArgumentError.new "unsupported cipher algorithm #{name.inspect}" unless cipher

    @ctx = LibCrypto.evp_cipher_ctx_new

    cipherinit(cipher: cipher, key: "\0" * 16, iv: "\0" * 16, enc: 1)
  end

  def update(data)
    ina = data.to_slice

    outa = Slice(UInt8).new(block_size)

    if LibCrypto.evp_cipherupdate(@ctx, outa.to_unsafe, out outl, ina.pointer(0), ina.size) != 1
      raise Error.new "EVP_CipherUpdate"
    end
    puts outl

    outa
  end

  def final
    outa = Slice(UInt8).new(block_size)

    if LibCrypto.evp_cipherfinal_ex(@ctx, outa.to_unsafe, out outl) != 1
      raise Error.new "EVP_CipherFinal_ex"
    end

    outa
  end

  def block_size
    LibCrypto.evp_cipher_block_size cipher
  end

  def key_len
    LibCrypto.evp_cipher_key_length cipher
  end

  def iv_len
    LibCrypto.evp_cipher_iv_length cipher
  end

  NULL = Pointer(Void).null

  private def cipherinit cipher = NULL, engine = NULL, key = Pointer(UInt8).null, iv = Pointer(UInt8).null, enc = -1
    if LibCrypto.evp_cipherinit_ex(@ctx, cipher, engine, key, iv, enc) != 1
      raise Error.new "EVP_CipherInit_ex"
    end

    nil
  end

  private def cipher
    LibCrypto.evp_cipher_ctx_cipher @ctx
  end
end

cipher = Cipher.new

output = MemoryIO.new

puts File.read("./spec/cipher_spec.ciphertext").bytes
output.write(cipher.update("DATA" * 5))
output.write(cipher.final)
puts output.to_slice
