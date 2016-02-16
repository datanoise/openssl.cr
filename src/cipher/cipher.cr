require "../openssl"

class OpenSSL::Cipher
  class Error < OpenSSL::OpenSSLError
  end

  def initialize(name)
    cipher = LibCrypto.evp_get_cipherbyname name
    raise ArgumentError.new "unsupported cipher algorithm #{name.inspect}" unless cipher

    @ctx = LibCrypto.evp_cipher_ctx_new
    # The EVP which has EVP_CIPH_RAND_KEY flag (such as DES3) allows
    # uninitialized key, but other EVPs (such as AES) does not allow it.
    # Calling EVP_CipherUpdate() without initializing key causes SEGV so
    # we set the data filled with "\0" as the key by default.
    cipherinit cipher: cipher, key: "\0" * LibCrypto::EVP_MAX_KEY_LENGTH
  end

  # auth_tag, auth_tag=
  # authenticated?

  def encrypt
    cipherinit enc: 1
  end

  def decrypt
    cipherinit enc: 0
  end

  def key=(key)
    raise ArgumentError.new "key length too short: wanted #{key_len}, got #{key.bytesize}" if key.bytesize < key_len
    cipherinit key: key
    key
  end

  def iv=(iv)
    raise ArgumentError.new "iv length too short: wanted #{iv_len}, got #{iv.bytesize}" if iv.bytesize < iv_len
    cipherinit iv: iv
    iv
  end

  def random_key
    iv = SecureRandom.random_bytes key_len
    self.key = key
  end

  def random_iv
    iv = SecureRandom.random_bytes iv_len
    self.iv = iv
  end

  # PKCS5 v1.5 implementation
  def pkcs5_keyivgen(pass, salt = Pointer(UInt8).null, iter = 2048, digest = "md5")
    raise "salt must be an 8-octet string" if salt != Pointer(UInt8).null && salt.bytesize != LibCrypto::PKCS5_SALT_LEN

    md = case digest
         when Digest
           LibCrypto.evp_md_ctx_md(digest)
         else
           LibCrypto.evp_get_digestbyname(digest)
         end
    raise ArgumentError.new "unknown digest #{digest.inspect}" unless md

    key = Array(UInt8).new(LibCrypto::EVP_MAX_KEY_LENGTH)
    iv = Array(UInt8).new(LibCrypto::EVP_MAX_IV_LENGTH)

    keybytes = LibCrypto.evp_bytestokey(@ctx, md, salt, pass, pass.bytesize, iter, key, iv)
    if keybytes == 0
      raise Error.new "EVP_BytesToKey"
    end
    key.length = keybytes

    cipherinit key: key, iv: iv

    LibCrypto.cleanse(key, keybytes)
    LibCrypto.cleanse(iv, LibCrypto::EVP_MAX_IV_LENGTH)
  end

  def reset
    cipherinit
  end

  def update(in)
    ina = case in
          when String
            in.bytes
          else
            in
          end

    outl = ina.size + 2*block_size
    outa = Slice(UInt8).new(outl)

    if LibCrypto.evp_cipherupdate(@ctx, outa, out out_size, ina, ina.size) != 1
      raise Error.new "EVP_CipherUpdate"
    end

    Array(UInt8).new(out_size) { |i| outa[i] }
  end

  def final
    outa = Slice(UInt8).new(block_size)

    if LibCrypto.evp_cipherfinal_ex(@ctx, outa, out outl) != 1
      raise Error.new "EVP_CipherFinal_ex"
    end

    Array(UInt8).new(outl) { |i| outa[i] }
  end

  def padding=(pad : Bool)
    if LibCrypto.evp_cipher_ctx_set_padding(@ctx, pad ? 1 : 0) != 1
      raise Error.new "EVP_CIPHER_CTX_set_padding"
    end

    pad
  end

  def name
    nid = LibCrypto.evp_cipher_nid cipher
    sn = LibCrypto.obj_nid2sn nid
    String.new sn
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

  def finalize
    LibCrypto.evp_cipher_ctx_free(@ctx) if @ctx
    @ctx = nil
  end

  NULL = Pointer(Void).null

  private def cipherinit(cipher = NULL, engine = NULL, key = Pointer(UInt8).null, iv = Pointer(UInt8).null, enc = -1)
    if LibCrypto.evp_cipherinit_ex(@ctx, cipher, engine, key, iv, enc) != 1
      raise Error.new "EVP_CipherInit_ex"
    end

    nil
  end

  private def cipher
    LibCrypto.evp_cipher_ctx_cipher @ctx
  end
end
