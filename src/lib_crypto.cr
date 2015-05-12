@[Link("crypto")]
lib LibCrypto
  alias EVP_MD = Void*

  struct EVP_MD_CTX_Struct
    digest: EVP_MD
    engine: Void*
    flags: UInt32
    pctx: Void*
    update_fun: Void*
  end
  alias EVP_MD_CTX = EVP_MD_CTX_Struct*

  fun evp_md_ctx_create = EVP_MD_CTX_create() : EVP_MD_CTX
  fun evp_get_digestbyname = EVP_get_digestbyname(name: UInt8*): EVP_MD
  fun evp_digestinit_ex = EVP_DigestInit_ex(ctx: EVP_MD_CTX, type: EVP_MD, engine: Void*) : Int32
  fun evp_md_ctx_destroy = EVP_MD_CTX_destroy(ctx: EVP_MD_CTX)
  fun evp_md_ctx_md = EVP_MD_CTX_md(ctx: EVP_MD_CTX) : EVP_MD
  fun evp_digestupdate = EVP_DigestUpdate(ctx: EVP_MD_CTX, data: UInt8*, count: LibC::SizeT) : Int32
  fun evp_md_size = EVP_MD_size(md: EVP_MD) : Int32
  fun evp_digestfinal_ex = EVP_DigestFinal_ex(ctx: EVP_MD_CTX, md: UInt8*, size: UInt32*) : Int32
  fun evp_md_block_size = EVP_MD_block_size(md: EVP_MD) : Int32
  fun evp_md_ctx_copy = EVP_MD_CTX_copy(dst: EVP_MD_CTX, src: EVP_MD_CTX) : Int32

  alias EVP_PKEY = Void*

  fun evp_signfinal = EVP_SignFinal(ctx: EVP_MD_CTX, sigret: UInt8*, siglen: UInt32*, pkey: EVP_PKEY) : Int32

  struct HMAC_CTX_Struct
    md: EVP_MD
    md_ctx: EVP_MD_CTX_Struct
    i_ctx: EVP_MD_CTX_Struct
    o_ctx: EVP_MD_CTX_Struct
    key_length: UInt32
    key: UInt8[128]
  end

  alias HMAC_CTX = HMAC_CTX_Struct*

  fun hmac_ctx_init = HMAC_CTX_init(ctx: HMAC_CTX)
  fun hmac_ctx_cleanup = HMAC_CTX_cleanup(ctx: HMAC_CTX)
  fun hmac_init_ex = HMAC_Init_ex(ctx: HMAC_CTX, key: Void*, len: Int32, md: EVP_MD, engine: Void*) : Int32
  fun hmac_update = HMAC_Update(ctx: HMAC_CTX, data: UInt8*, len: LibC::SizeT) : Int32
  fun hmac_final = HMAC_Final(ctx: HMAC_CTX, md: UInt8*, len: UInt32*) : Int32
  fun hmac_ctx_copy = HMAC_CTX_copy(dst: HMAC_CTX, src: HMAC_CTX) : Int32

  alias ASN1_OBJECT = Void*

  fun obj_txt2obj = OBJ_txt2obj(s: UInt8*, no_name: Int32) : ASN1_OBJECT
  fun obj_nid2sn = OBJ_nid2sn(n: Int32) : UInt8*
  fun obj_obj2nid = OBJ_obj2nid(obj: ASN1_OBJECT) : Int32
  fun asn1_object_free = ASN1_OBJECT_free(obj: ASN1_OBJECT)

end
