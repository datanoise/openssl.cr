require "./lib_openssl"

module OpenSSL
  class OpenSSLError < Exception
  end

  LibSSL.ssl_library_init()
  LibSSL.openssl_add_all_algorithms()
  LibSSL.err_load_crypto_strings()
  LibSSL.ssl_load_error_strings()
end

require "./*"
