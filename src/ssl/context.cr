module OpenSSL::SSL
  class SSLError < OpenSSLError; end

  @[Flags]
  enum VerifyMode
    PEER = LibSSL::SSL_VERIFY_PEER
    NONE = LibSSL::SSL_VERIFY_NONE
    FAIL_IF_NO_PEER_CERT = LibSSL::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
  end

  enum FileType
    PEM = LibSSL::X509_FILETYPE_PEM
    ASN1 = LibSSL::X509_FILETYPE_ASN1
    DEFAULT = LibSSL::X509_FILETYPE_DEFAULT
  end

  @[Flags]
  enum ContextOptions : Int64
    LEGACY_SERVER_CONNECT                  = 0x00000004
    NETSCAPE_REUSE_CIPHER_CHANGE_BUG       = 0x00000008
    TLSEXT_PADDING                         = 0x00000010
    MICROSOFT_BIG_SSLV3_BUFFER             = 0x00000020
    SAFARI_ECDHE_ECDSA_BUG                 = 0x00000040
    SSLEAY_080_CLIENT_DH_BUG               = 0x00000080
    TLS_D5_BUG                             = 0x00000100
    TLS_BLOCK_PADDING_BUG                  = 0x00000200
    DONT_INSERT_EMPTY_FRAGMENTS            = 0x00000800
    ALL                                    = 0x80000BFF
    NO_QUERY_MTU                           = 0x00001000
    COOKIE_EXCHANGE                        = 0x00002000
    NO_TICKET                              = 0x00004000
    CISCO_ANYCONNECT                       = 0x00008000
    NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000
    NO_COMPRESSION                         = 0x00020000
    ALLOW_UNSAFE_LEGACY_RENEGOTIATION      = 0x00040000
    SINGLE_ECDH_USE                        = 0x00080000
    SINGLE_DH_USE                          = 0x00100000
    CIPHER_SERVER_PREFERENCE               = 0x00400000
    TLS_ROLLBACK_BUG                       = 0x00800000
    NO_SSLV2                               = 0x00000000
    NO_SSLV3                               = 0x02000000
    NO_TLSV1                               = 0x04000000
    NO_TLSV1_2                             = 0x08000000
    NO_TLSV1_1                             = 0x10000000
    NO_DTLSV1                              = 0x04000000
    NO_DTLSV1_2                            = 0x08000000
  end

  class Context
    alias VerifyCallback = (Bool, X509::StoreContext) -> Bool

    @@index = begin
                index = LibSSL.ssl_ctx_get_ex_new_index(0_i64, nil, nil, nil, nil)
                if index < 0
                  raise SSLError.new "invalid index"
                end
                index
              end

    def initialize(@handle : LibSSL::SSL_CTX) 
      raise SSLError.new "invalid handle" unless @handle
    end

    def initialize(method : Method)
      initialize(LibSSL.ssl_ctx_new(method.to_unsafe))
      if method == Method::DTLSv1 || method == Method::DTLSv1_2
        self.read_ahead = 1
      end
    end

    def finalize
      LibSSL.ssl_ctx_free(self)
    end

    def set_verify(mode : VerifyMode, &block : VerifyCallback)
      LibSSL.ssl_ctx_set_ex_data(self, @@index, Box(VerifyCallback).box(block))
      LibSSL.ssl_ctx_set_verify(self, mode.value, ->Context.raw_verify)
    end

    protected def self.raw_verify(preverify_ok : Int32, ctx : LibCrypto::X509_STORE_CTX)
      idx = LibSSL.ssl_get_ex_data_x509_store_ctx_idx()
      ssl = LibSSL.x509_store_ctx_get_ex_data(ctx, idx)
      ssl_ctx = LibSSL.ssl_get_ssl_ctx(ssl)
      verify = LibSSL.ssl_ctx_get_ex_data(ssl_ctx, @@index)
      callback = Box(VerifyCallback).unbox(verify)

      x509_ctx = X509::StoreContext.new ctx
      if callback
        callback.call(preverify_ok != 0, x509_ctx) ? 1 : 0
      else
        preverify_ok
      end
    end

    def read_ahead=(v)
      ssl_ctx_set_read_ahead(v.to_i64)
    end

    def verify_depth=(depth)
      LibSSL.ssl_ctx_set_verify_depth(self, depth)
    end

    def ca_file=(file)
      if LibSSL.ssl_ctx_load_verify_locations(self, file, nil) == 0
        raise SSLError.new "unable to set CA file"
      end
    end

    def set_certificate_file(file, type : FileType)
      if LibSSL.ssl_ctx_use_certificate_file(self, file, type.value) == 0
        raise SSLError.new "unable to set certificate file"
      end
    end

    def certificate_file=(file)
      set_certificate_file(file, FileType::PEM)
    end

    def certificate_chain_file=(file)
      if LibSSL.ssl_ctx_use_certificate_chain_file(self, file) == 0
        raise SSLError.new "unable to load certificate chain"
      end
    end

    def certificate=(cert)
      if LibSSL.ssl_ctx_use_certificate(self, cert) == 0
        raise SSLError.new
      end
    end

    def add_extra_chain_cert(cert)
      if ssl_ctx_add_extra_chain_cert(cert) == 0
        raise SSLError.new
      end
    end

    def set_private_key_file(file, type : FileType)
      if LibSSL.ssl_ctx_use_privatekey_file(self, file, type.value) == 0
        raise SSLError.new
      end
    end

    def private_key_file=(file)
      set_private_key_file(file, FileType::PEM)
    end

    def private_key=(pkey)
      if LibSSL.ssl_ctx_use_privatekey(self, pkey) == 0
        raise SSLError.new
      end
    end

    def check_private_key
      if LibSSL.ssl_ctx_check_private_key(self) == 0
        raise SSLError.new
      end
    end

    def cipher_list=(list)
      if LibSSL.ssl_ctx_set_cipher_list(self, list) == 0
        raise SSLError.new
      end
    end

    def set_default_verify_paths
      LibSSL.ssl_ctx_set_default_verify_paths(self)
    end

    def options=(option)
      ssl_ctx_set_options(option)
    end

    def options
      ssl_ctx_get_options
    end

    def clear_options(option : ContextOptions)
      ssl_ctx_clear_options(option)
    end

    def to_unsafe
      @handle
    end

    private def ssl_ctx_set_read_ahead(v : Int64)
      LibSSL.ssl_ctx_ctrl(self, LibSSL::SSL_CTRL_SET_READ_AHEAD, v, nil)
    end

    private def ssl_ctx_add_extra_chain_cert(cert : X509::Certificate)
      LibSSL.ssl_ctx_ctrl(self, LibSSL::SSL_CTRL_EXTRA_CHAIN_CERT, 0_i64, cert.to_unsafe)
    end

    private def ssl_ctx_clear_options(option : ContextOptions)
      LibSSL.ssl_ctx_ctrl(self, LibSSL::SSL_CTRL_CLEAR_OPTIONS, option.value, nil)
    end

    private def ssl_ctx_get_options
      LibSSL.ssl_ctx_ctrl(self, LibSSL::SSL_CTRL_OPTIONS, 0_i64, nil)
    end

    private def ssl_ctx_set_options(option : ContextOptions)
      LibSSL.ssl_ctx_ctrl(self, LibSSL::SSL_CTRL_OPTIONS, option.value, nil)
    end
  end
end
