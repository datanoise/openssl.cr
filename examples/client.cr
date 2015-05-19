require "socket"
require "../src/openssl"

include OpenSSL

TCPSocket.open("localhost", 5555) do |socket|
  ssl_ctx = SSL::Context.new(SSL::Method::SSLv23)
  ssl_ctx.ca_file = "my_cert.pem"
  ssl_ctx.set_verify SSL::VerifyMode::PEER do |ok, store|
    certificate = store.certificate
    pp ok
    pp certificate.subject_name
    true
  end
  SSL::Socket.new_client(socket, ssl_ctx) do |client|
    client.write("hello world".to_slice)
    buf :: UInt8[512]
    slice = buf.to_slice
    len = client.read(slice)
    puts "From server: #{String.new slice[0,len]}"
  end
end

