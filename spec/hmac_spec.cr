require "spec"
require "../src/openssl"

describe OpenSSL::HMAC do
  it "should be able to calculate HMAC" do
    hmac = OpenSSL::HMAC.new "my key", OpenSSL::Digest::SHA1.new
    hmac << "test string"
    hmac.hexdigest.should eq("6443e35a1ff6a04ee9936a746dba7b6006763fd1")
  end
end
