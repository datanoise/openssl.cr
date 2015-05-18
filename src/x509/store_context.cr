class OpenSSL::X509::StoreContext
  class StoreContextError < OpenSSLError; end

  def initialize(@ctx: LibCrypto::X509_STORE_CTX)
    raise StoreContextError.new "invalid handle" unless @ctx
  end

  def get_error
    LibCrypto.x509_store_ctx_get_error(self)
  end

  def certificate
    LibCrypto.x509_store_ctx_get_current_cert(self)
  end

  def to_unsafe
    @ctx
  end
end
