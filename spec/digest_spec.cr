require "spec"
require "../src/openssl"

describe OpenSSL::Digest do
  it "should be able to calculate SHA1" do
    digest = OpenSSL::Digest.new("SHA1")
    digest << "test string"
    digest.base64digest.should eq("ZhKVycv51rL2QoQUUEqN7tMCBkE=\n")
    digest.hexdigest.should eq("661295c9cbf9d6b2f6428414504a8deed3020641")
  end

  it "should be able to access digest with a specific class" do
    digest = OpenSSL::Digest::SHA1.new
    digest << "test string"
    digest.base64digest.should eq("ZhKVycv51rL2QoQUUEqN7tMCBkE=\n")
    digest.hexdigest.should eq("661295c9cbf9d6b2f6428414504a8deed3020641")
  end
end
