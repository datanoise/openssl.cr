require "./src/openssl"

dsa = OpenSSL::PKey::DSA.generate(1024)
pem = MemoryIO.new
p dsa.to_pem(pem)

p pem.to_s
new_dsa = OpenSSL::PKey::DSA.new(pem.to_s)
p new_dsa.to_pem
p dsa.to_pem == new_dsa.to_pem
