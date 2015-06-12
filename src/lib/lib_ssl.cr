require "./lib_crypto"

@[Link("ssl")]
lib LibSSL

  fun ssl_library_init = SSL_library_init()
  fun openssl_add_all_algorithms = OPENSSL_add_all_algorithms_noconf()
  fun err_load_crypto_strings = ERR_load_crypto_strings()
  fun ssl_load_error_strings = SSL_load_error_strings()

  alias SSL_METHOD = Void*

  # fun sslv2_method = SSLv2_method() : SSL_METHOD
  fun sslv3_method = SSLv3_method() : SSL_METHOD
  fun sslv23_method = SSLv23_method() : SSL_METHOD
  fun tlsv1_method = TLSv1_method() : SSL_METHOD
  fun tlsv1_1_method = TLSv1_1_method() : SSL_METHOD
  fun tlsv1_2_method = TLSv1_2_method() : SSL_METHOD
  fun dtlsv1_method = DTLSv1_method() : SSL_METHOD
  fun dtlsv1_2_method = DTLSv1_2_method() : SSL_METHOD

  alias SSL_CTX = Void*

  SSL_VERIFY_NONE = 0
  SSL_VERIFY_PEER = 1
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
  X509_FILETYPE_PEM = 1
  X509_FILETYPE_ASN1 = 2
  X509_FILETYPE_DEFAULT = 3

  alias VerifyCallback = (Int32, LibCrypto::X509_STORE_CTX) -> Int32

  fun ssl_ctx_new = SSL_CTX_new(meth: SSL_METHOD) : SSL_CTX
  fun ssl_ctx_free = SSL_CTX_free(ctx: SSL_CTX)
  fun ssl_ctx_get_ex_new_index = SSL_CTX_get_ex_new_index(argl: Int64, argp: Void*, new_func: Void*,
                                                          dup_func: Void*, free_func: Void*) : Int32
  fun ssl_ctx_set_ex_data = SSL_CTX_set_ex_data(ctx: SSL_CTX, idx: Int32, arg: Void*) : Int32
  fun ssl_ctx_set_verify = SSL_CTX_set_verify(ctx: SSL_CTX, mode: Int32, ct: VerifyCallback)
  fun ssl_get_ex_data_x509_store_ctx_idx = SSL_get_ex_data_X509_STORE_CTX_idx() : Int32
  fun x509_store_ctx_get_ex_data = X509_STORE_CTX_get_ex_data(ctx: LibCrypto::X509_STORE_CTX, idx: Int32) : Void*
  fun ssl_get_ssl_ctx = SSL_get_SSL_CTX(ssl: Void*) : SSL_CTX
  fun ssl_ctx_get_ex_data = SSL_CTX_get_ex_data(ctx: SSL_CTX, idx: Int32) : Void*
  fun ssl_ctx_set_verify_depth = SSL_CTX_set_verify_depth(ctx: SSL_CTX, depth: Int32)
  fun ssl_ctx_load_verify_locations = SSL_CTX_load_verify_locations(ctx: SSL_CTX, ca_file: UInt8*, ca_path: UInt8*) : Int32
  fun ssl_ctx_use_certificate_file = SSL_CTX_use_certificate_file(ctx: SSL_CTX, file: UInt8*, type: Int32) : Int32
  fun ssl_ctx_use_certificate = SSL_CTX_use_certificate(ctx: SSL_CTX, x509: LibCrypto::X509) : Int32
  fun ssl_ctx_use_privatekey_file = SSL_CTX_use_PrivateKey_file(ctx: SSL_CTX, file: UInt8*, type: Int32) : Int32
  fun ssl_ctx_use_privatekey = SSL_CTX_use_PrivateKey(ctx: SSL_CTX, pkey: LibCrypto::EVP_PKEY) : Int32
  fun ssl_ctx_check_private_key = SSL_CTX_check_private_key(ctx: SSL_CTX) : Int32
  fun ssl_ctx_set_cipher_list = SSL_CTX_set_cipher_list(ctx: SSL_CTX, str: UInt8*) : Int32
  fun ssl_ctx_set_default_verify_paths = SSL_CTX_set_default_verify_paths(ctx: SSL_CTX) : Int32
  fun ssl_ctx_use_certificate_chain_file = SSL_CTX_use_certificate_chain_file(ctx: SSL_CTX, file: UInt8*) : Int32

  SSL_CTRL_SET_READ_AHEAD = 41
  SSL_CTRL_EXTRA_CHAIN_CERT = 14
  SSL_CTRL_CLEAR_OPTIONS = 77
  SSL_CTRL_OPTIONS = 32
  fun ssl_ctx_ctrl = SSL_CTX_ctrl(ctx: SSL_CTX, cmd: Int32, larg: Int64, parg: Void*) : Int64

  alias SSL = Void*

  fun ssl_new = SSL_new(ctx: SSL_CTX) : SSL
  fun ssl_free = SSL_free(ssl: SSL)
  fun ssl_set_bio = SSL_set_bio(ssl: SSL, rbio: LibCrypto::BIO, wbio: LibCrypto::BIO)
  fun ssl_connect = SSL_connect(ssl: SSL) : Int32
  fun ssl_accept = SSL_accept(ssl: SSL) : Int32
  fun ssl_read = SSL_read(ssl: SSL, buf: UInt8*, num: Int32) : Int32
  fun ssl_write = SSL_write(ssl: SSL, buf: UInt8*, num: Int32) : Int32
  fun ssl_shutdown = SSL_shutdown(ssl: SSL) : Int32
  fun ssl_get_peer_certificate = SSL_get_peer_certificate(ssl: SSL) : LibCrypto::X509
  fun ssl_renegotiate = SSL_renegotiate(ssl: SSL) : Int32
  fun ssl_pending = SSL_pending(ssl: SSL) : Int32
  fun ssl_do_handshake = SSL_do_handshake(ssl: SSL) : Int32

  SSL_ERROR_NONE = 0
  SSL_ERROR_SSL = 1
  SSL_ERROR_SYSCALL = 5
  SSL_ERROR_WANT_ACCEPT = 8
  SSL_ERROR_WANT_CONNECT = 7
  SSL_ERROR_WANT_READ = 2
  SSL_ERROR_WANT_WRITE = 3
  SSL_ERROR_WANT_X509_LOOKUP = 4
  SSL_ERROR_ZERO_RETURN = 6

  fun ssl_get_error = SSL_get_error(ssl: SSL, ret: Int32) : Int32
end
