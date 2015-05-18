module IO
  def self.copy(src: IO, dst: IO)
    buffer :: UInt8[1024]
    count = 0
    while (len = src.read(buffer.to_slice)) > 0
      dst.write(buffer.to_slice[0,len.to_i32])
      count += len
    end
    len < 0 ? len : count
  end
end
