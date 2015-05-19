require "../src/openssl"

include OpenSSL::X509

certificate, pkey =
  Generator.generate do |g|
    g.bitlength = 2048
    g.valid_period = 365 * 2
    g.cn = "MyName"
    g.usage << Generator::KeyUsage::DigitalSignature
  end

File.open("my_cert.pem", "w") do |f|
  certificate.to_pem(f)
end

File.open("my_key.pem", "w") do |f|
  pkey.to_pem(f)
end
