# openssl.cr

This library provides binding for OpenSSL library.

# Status

*Alpha*

# Requirements

- Crystal language version 0.9 and higher.
- openssl version 1.0.2a or higher

On Mac OSX the default openssl is quite outdated. You can use `homebrew` to install the latest openssl:

```
$ brew install openssl
```

You will also need to set up the `LIBRARY_PATH` correspondingly in order to be able to compile the library:

```
export LIBRARY_PATH=`brew --prefix openssl`/lib
```

# Goal

The standard crystal library comes with quite limited support for OpenSSL,
lacking many features like SSL verification, the X509 certificate API, etc.
This library is aimed to remedy the situation.

# Usage

This is an example of specifying the custom verification callback when
initiating HTTPS connection:

```crystal
require "socket"
require "./src/openssl"

include OpenSSL

TCPSocket.open("www.google.com", 443) do |socket|
  ssl_ctx = SSL::Context.new(SSL::Method::SSLv23)
  ssl_ctx.set_default_verify_paths
  ssl_ctx.set_verify SSL::VerifyMode::PEER do |ok, store|
    certificate = store.certificate
    pp ok
    pp certificate.subject_name
    ok
  end
  SSL::Socket.new_client(socket, ssl_ctx) do |client|
    client.write("GET / HTTP/1.1\r\n".to_slice)
    client.write("\r\n".to_slice)
    buf :: UInt8[512]
    slice = buf.to_slice
    loop do
      len = client.read(slice)
      break if len == 0
      puts "From server: #{String.new slice[0,len]}"
    end
  end
end
```

This is the basic usage of SSL server:

```crystal
require "socket"
require "../src/openssl"

include OpenSSL

tcp_server = TCPServer.new(5555)

ssl_ctx = SSL::Context.new(SSL::Method::SSLv23)
ssl_ctx.certificate_file = "my_cert.pem"
ssl_ctx.private_key_file = "my_key.pem"

loop do
  client = tcp_server.accept
  SSL::Socket.new_server(client, ssl_ctx) do |client|
    buf :: UInt8[512]
    slice = buf.to_slice
    loop do
      len = client.read(slice)
      if len > 0
        client.write(slice[0, len])
      else
        break
      end
    end
  end
end
```

If you have a need to generate your own self-signed certificate:

```crystal
certificate, pkey =
  OpenSSL::X509::Generator.generate do |g|
    g.bitlength = 2048
    g.valid_period = 365 * 2
    g.cn = "MyName"
    g.usage << Generator::KeyUsage::DigitalSignature
  end
puts certificate.to_pem
```

# ToDo

- Extend X509::Certificate to get access to extentions, X509CRL, etc.
- X509::Generate is quite primitive at the moment.

# License

MIT clause - see LICENSE for more details.



