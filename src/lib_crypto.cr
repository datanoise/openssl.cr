@[Link("crypto")]
lib LibCrypto
  alias EVP_MD_CTX = Void*
  alias EVP_MD = Void*

  fun evp_md_ctx_create = EVP_MD_CTX_create() : EVP_MD_CTX
  fun evp_get_digestbyname = EVP_get_digestbyname(name: UInt8*): EVP_MD
  fun evp_digestinit_ex = EVP_DigestInit_ex(ctx: EVP_MD_CTX, type: EVP_MD, engine: Void*) : Int32
  fun evp_md_ctx_destroy = EVP_MD_CTX_destroy(ctx: EVP_MD_CTX)
  fun evp_md_ctx_md = EVP_MD_CTX_md(ctx: EVP_MD_CTX) : EVP_MD
  fun evp_digestupdate = EVP_DigestUpdate(ctx: EVP_MD_CTX, data: UInt8*, count: LibC::SizeT) : Int32
  fun evp_md_size = EVP_MD_size(md: EVP_MD) : Int32
  fun evp_digestfinal_ex = EVP_DigestFinal_ex(ctx: EVP_MD_CTX, md: UInt8*, size: UInt32*) : Int32
  fun evp_md_block_size = EVP_MD_block_size(md: EVP_MD) : Int32

  alias ASN1_OBJECT = Void*

  fun obj_txt2obj = OBJ_txt2obj(s: UInt8*, no_name: Int32) : ASN1_OBJECT
  fun obj_nid2sn = OBJ_nid2sn(n: Int32) : UInt8*
  fun obj_obj2nid = OBJ_obj2nid(obj: ASN1_OBJECT) : Int32
  fun asn1_object_free = ASN1_OBJECT_free(obj: ASN1_OBJECT)
end
