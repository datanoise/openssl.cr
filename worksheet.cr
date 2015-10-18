require "./src/lib/lib_ssl"
# require "secure_random"

NULL = Pointer(Void).null
# initialize
cipher = LibCrypto.evp_get_cipherbyname "aes-128-cbc"
ctx = LibCrypto.evp_cipher_ctx_new

# init

key = "\0" * 16
iv = "\0" * 16
LibCrypto.evp_cipherinit_ex(ctx, cipher, NULL, key, iv, 1)

# key_len = LibCrypto.evp_cipher_key_length cipher
# iv_len = LibCrypto.evp_cipher_iv_length cipher

puts cipher
puts ctx

# puts key_len.inspect
# puts iv_len.inspect
