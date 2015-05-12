@[Link("ssl")]
lib LibSSL

  fun ssl_library_init = SSL_library_init()
  fun openssl_add_all_algorithms = OPENSSL_add_all_algorithms_noconf()
  fun err_load_crypto_strings = ERR_load_crypto_strings()
  fun ssl_load_error_strings = SSL_load_error_strings()

end
