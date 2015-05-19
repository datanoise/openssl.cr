require "socket"
require "../src/openssl"

include OpenSSL

tcp_server = TCPServer.new( 5555 )

ssl_ctx = SSL::Context.new(SSL::Method::SSLv23)

ssl_ctx.certificate_file = "my_cert.pem"
ssl_ctx.private_key_file = "my_key.pem"

loop do
  client = tcp_server.accept
  SSL::Socket.new_server(client, ssl_ctx) do |client|
    buf :: UInt8[512]
    loop do
      len = client.read(buf.to_slice)
      if len > 0
        client.write(buf.to_slice[0, len])
      else
        break
      end
    end
  end
end

