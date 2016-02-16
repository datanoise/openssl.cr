require "../openssl"

class OpenSSL::SSL::Socket
  include IO

  def initialize(io, @context : Context)
    @handle = LibSSL.ssl_new(@context)
    raise SSLError.new "invalid handle" unless @handle
    @bio = BIO.new(io)
    LibSSL.ssl_set_bio(self, @bio, @bio)
  end

  def self.new_client(io, context : Context)
    socket = new(io, context)
    socket.connect
    begin
      yield socket
    ensure
      socket.close
    end
  end

  def self.new_server(io, context : Context)
    socket = new(io, context)
    socket.accept
    begin
      yield socket
    ensure
      socket.close
    end
  end

  def do_handshake
    ret = LibSSL.ssl_do_handshake(self)
    check_error(ret)
  end

  def pending
    LibSSL.ssl_pending(self)
  end

  def renegotiate
    ret = LibSSL.ssl_renegotiate(self)
    check_error(ret)
  end

  def finalize
    LibSSL.ssl_free(self)
  end

  def connect
    LibSSL.ssl_connect(self)
  end

  def accept
    LibSSL.ssl_accept(self)
  end

  def read(slice : Slice(UInt8))
    read(slice, slice.size)
  end

  def read(slice : Slice(UInt8), count)
    ret = LibSSL.ssl_read(self, slice.pointer(count), count)
    check_error(ret)
    ret
  end

  def write(slice : Slice(UInt8))
    write(slice, slice.size)
  end

  def write(slice : Slice(UInt8), count)
    ret = LibSSL.ssl_write(self, slice.pointer(count), count)
    check_error(ret)
    ret
  end

  def close
    while LibSSL.ssl_shutdown(self) == 0; end
  end

  def peer_certificate
    x509 = LibSSL.ssl_get_peer_certificate(self)
    Certificate.new x509 if x509
  end

  def to_unsafe
    @handle
  end

  private def get_error(ret)
    LibSSL.ssl_get_error(self, ret)
  end

  private def check_error(ret)
    if get_error(ret) == LibSSL::SSL_ERROR_SSL
      raise SSLError.new
    end
  end
end
