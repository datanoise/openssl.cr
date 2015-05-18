enum OpenSSL::SSL::Method
  # SSLv2
  SSLv23
  SSLv3
  TLSv1
  TLSv1_1
  TLSv1_2
  DTLSv1
  DTLSv1_2

  def to_unsafe
    case self
    # when SSLv2
    #   LibSSL.sslv2_method()
    when SSLv23
      LibSSL.sslv23_method()
    when SSLv3
      LibSSL.sslv3_method()
    when TLSv1
      LibSSL.tlsv1_method()
    when TLSv1_1
      LibSSL.tlsv1_1_method()
    when TLSv1_2
      LibSSL.tlsv1_2_method()
    when DTLSv1
      LibSSL.dtlsv1_method()
    when DTLSv1_2
      LibSSL.dtlsv1_2_method()
    end
  end
end
