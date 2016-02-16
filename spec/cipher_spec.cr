require "spec"
require "../src/openssl"

describe OpenSSL::Cipher do
  it "encrypts/decrypts" do
    cipher = "aes-128-cbc"
    c1 = OpenSSL::Cipher.new(cipher)
    c2 = OpenSSL::Cipher.new(cipher)
    key = "\0" * 16
    iv = "\0" * 16
    data = "DATA" * 5
    ciphertext = File.read(File.dirname(__FILE__) + "/cipher_spec.ciphertext").bytes

    c1.name.should eq(c2.name)

    c1.encrypt
    c2.encrypt
    c1.key = c2.key = key
    c1.iv = c2.iv = iv

    s1 = c1.update("DATA")
    s1 += c1.update("DATA" * 4)
    s1 += c1.final
    s2 = c2.update(data) + c2.final
    s1.should eq(ciphertext)
    s1.should eq(s2)

    c1.decrypt
    c2.decrypt
    c1.key = c2.key = key
    c1.iv = c2.iv = iv

    s1 = c1.update(s1) + c1.final
    s2 = c2.update(s2) + c2.final
    String.new(s1.to_unsafe).should eq(data)
    s1.should eq(s2)
  end
end
