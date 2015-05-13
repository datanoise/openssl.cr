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
  alias EVP_CIPHER = Void*

  fun evp_pkey_size = EVP_PKEY_size(pkey: EVP_PKEY) : Int32
  fun evp_signfinal = EVP_SignFinal(ctx: EVP_MD_CTX, sigret: UInt8*, siglen: UInt32*, pkey: EVP_PKEY) : Int32
  fun evp_verifyfinal = EVP_VerifyFinal(ctx: EVP_MD_CTX, sigbuf: UInt8*, siglen: UInt32, pkey: EVP_PKEY) : Int32
  fun evp_pkey_new = EVP_PKEY_new() : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(pkey: EVP_PKEY)

  NID_rsaEncryption = 6

  fun evp_pkey_assign = EVP_PKEY_assign(pkey: EVP_PKEY, type: Int32, key: Void*) : Int32

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

  alias BIO = Void*
  alias BIO_METHOD = Void*

  fun bio_s_mem = BIO_s_mem() : BIO_METHOD
  fun bio_new = BIO_new(type: BIO_METHOD) : BIO
  fun bio_free_all = BIO_free_all(bio: BIO)
  fun bio_read = BIO_read(bio: BIO, data: UInt8*, len: Int32) : Int32
  fun bio_write = BIO_write(bio: BIO, data: UInt8*, len: Int32) : Int32

  alias PasswordCallback = (UInt8*, Int32, Int32, Void*) -> Int32

  alias RSA = Void*

  fun rsa_generate_key = RSA_generate_key(bits: Int32, e: UInt32, cb: (Int32, Int32, Void*) ->, ud: Void*) : RSA
  fun rsapublickey_dup = RSAPublicKey_dup(rsa: RSA) : RSA
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pk: EVP_PKEY) : RSA
  fun rsa_print = RSA_print(bio: BIO, rsa: RSA, off: Int32) : Int32
  fun i2d_rsaprivatekey = i2d_RSAPrivateKey(rsa: RSA, buf: UInt8**) : Int32
  fun i2d_rsa_pubkey = i2d_RSA_PUBKEY(rsa: RSA, buf: UInt8**) : Int32
  fun rsa_size = RSA_size(rsa: RSA) : Int32

  enum Padding
    PKCS1_PADDING      = 1
    SSLV23_PADDING     = 2
    NO_PADDING         = 3
    PKCS1_OAEP_PADDING = 4
    X931_PADDING       = 5
    PKCS1_PSS_PADDING  = 6
  end

  fun rsa_public_encrypt = RSA_public_encrypt(flen: Int32, from: UInt8*, to: UInt8*, rsa: RSA, p: Padding) : Int32
  fun rsa_public_decrypt = RSA_public_decrypt(flen: Int32, from: UInt8*, to: UInt8*, rsa: RSA, p: Padding) : Int32
  fun rsa_private_encrypt = RSA_private_encrypt(flen: Int32, from: UInt8*, to: UInt8*, rsa: RSA, p: Padding) : Int32
  fun rsa_private_decrypt = RSA_private_decrypt(flen: Int32, from: UInt8*, to: UInt8*, rsa: RSA, p: Padding) : Int32

  fun pem_read_bio_privatekey = PEM_read_bio_PrivateKey(bio: BIO, pk: EVP_PKEY*, cb: PasswordCallback, user_data: Void*) : EVP_PKEY
  fun pem_write_bio_rsaprivatekey = PEM_write_bio_RSAPrivateKey(bio: BIO, rsa: RSA, enc: EVP_CIPHER, kstr: UInt8*, klen: Int32, cb: PasswordCallback, user_data: Void*) : Int32
  fun pem_write_bio_rsa_pubkey = PEM_write_bio_RSA_PUBKEY(bio: BIO, rsa: RSA)
end
