require "./lib/lib_ssl"

module OpenSSL
  class OpenSSLError < Exception
    getter err
    getter err_msg

    def initialize(msg = nil)
      unless (err = @err = LibCrypto.get_error) == 0
        @err_msg = String.new(LibCrypto.err_error_string(err, nil))
        msg = msg ? "#{msg}: #{@err_msg}": @err_msg
      end
      super(msg)
    end
  end

  LibSSL.ssl_library_init()
  LibSSL.openssl_add_all_algorithms()
  LibSSL.err_load_crypto_strings()
  LibSSL.ssl_load_error_strings()
end

require "./digest/*"
require "./cipher/*"
require "./bio/*"
require "./pkey/*"
require "./x509/*"
require "./ssl/*"
