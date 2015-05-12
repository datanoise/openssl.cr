require "./openssl"

module OpenSSL
  class Digest
    class DigestError < OpenSSLError; end

    getter name

    def initialize(@name)
      md = LibCrypto.evp_get_digestbyname(@name)
      unless md
        oid = LibCrypto.obj_txt2obj(@name, 0)
        md = LibCrypto.evp_get_digestbyname(LibCrypto.obj_nid2sn(LibCrypto.obj_obj2nid(oid)))
        LibCrypto.asn1_object_free(oid)
      end
      unless md
        raise "Unsupported digest algoritm: #{@name}"
      end
      # @ctx = Pointer(LibCrypto::EVP_MD_CTX).malloc(1)
      ctx = LibCrypto.evp_md_ctx_create()
      unless ctx
        raise DigestError.new "Digest initialization failed."
      end
      if LibCrypto.evp_digestinit_ex(ctx, md, nil) != 1
        raise DigestError.new "Digest initialization failed."
      end
      @ctx = ctx
    end

    def finalize
      LibCrypto.evp_md_ctx_destroy(@ctx)
    end

    def reset
      if LibCrypto.evp_digestinit_ex(@ctx, LibCrypto.evp_md_ctx_md(@ctx), nil) != 1
        raise DigestError.new "Digest initialization failed."
      end
      self
    end

    def update(data)
      LibCrypto.evp_digestupdate(@ctx, data.cstr, LibC::SizeT.cast(data.length))
      self
    end

    def <<(data)
      update(data)
    end

    def digest
      size = digest_size
      data = Slice(UInt8).new(size)
      LibCrypto.evp_digestfinal_ex(@ctx, data, nil)
      data
    end

    def digest_size
      LibCrypto.evp_md_size(LibCrypto.evp_md_ctx_md(@ctx))
    end

    def block_size
      LibCrypto.evp_md_block_size(LibCrypto.evp_md_ctx_md(@ctx))
    end
  end
end
