module System.Crypto.Pkcs11Imports
where

#include "pkcs11import.h"

type CK_FLAGS = {#type CK_FLAGS#}
type CK_ULONG = {#type CK_ULONG#}
type CK_MECHANISM_TYPE = {#type CK_MECHANISM_TYPE#}
type CK_RV = {#type CK_RV#}


{#enum define MechType {
    CKM_RSA_PKCS_KEY_PAIR_GEN as RsaPkcsKeyPairGen,
    CKM_RSA_PKCS as RsaPkcs,
    CKM_RSA_9796 as Rsa9796,
    CKM_RSA_X_509 as RsaX509,
    CKM_MD2_RSA_PKCS               as Md2RsaPkcs,-- 0x00000004
    CKM_MD5_RSA_PKCS               as Md5RsaPkcs,-- 0x00000005
    CKM_SHA1_RSA_PKCS              as Sha1RsaPkcs,-- 0x00000006
    CKM_RIPEMD128_RSA_PKCS         as RipeMd128RsaPkcs,-- 0x00000007
    CKM_RIPEMD160_RSA_PKCS         as RipeMd160RsaPkcs,-- 0x00000008
    CKM_RSA_PKCS_OAEP              as RsaPkcsOaep,-- 0x00000009
    CKM_RSA_X9_31_KEY_PAIR_GEN     as RsaX931KeyPairGen,-- 0x0000000A
    CKM_RSA_X9_31                  as RsaX931,-- 0x0000000B
    CKM_SHA1_RSA_X9_31             as Sha1RsaX931,-- 0x0000000C
    CKM_RSA_PKCS_PSS               as RsaPkcsPss,-- 0x0000000D
    CKM_SHA1_RSA_PKCS_PSS          as Sha1RsaPkcsPss,-- 0x0000000E
    CKM_DSA_KEY_PAIR_GEN           as DsaKeyPairGen,-- 0x00000010
    CKM_DSA                        as Dsa,-- 0x00000011
    CKM_DSA_SHA1                   as DsaSha1,-- 0x00000012
    CKM_DH_PKCS_KEY_PAIR_GEN       as DhPkcsKeyPairGen,-- 0x00000020
    CKM_DH_PKCS_DERIVE             as DhPkcsDerive,-- 0x00000021
    CKM_X9_42_DH_KEY_PAIR_GEN      as X942DhKeyPairGen,-- 0x00000030
    CKM_X9_42_DH_DERIVE            as X942DhDerive,-- 0x00000031
    CKM_X9_42_DH_HYBRID_DERIVE     as X942DhHybridDerive,-- 0x00000032
    CKM_X9_42_MQV_DERIVE           as X942MqvDerive,-- 0x00000033
    CKM_SHA256_RSA_PKCS            as Sha256RsaPkcs,-- 0x00000040
    CKM_SHA384_RSA_PKCS            as Sha384RsaPkcs,-- 0x00000041
    CKM_SHA512_RSA_PKCS            as Sha512RsaPkcs,-- 0x00000042
    CKM_SHA256_RSA_PKCS_PSS        as Sha256RsaPkcsPss,-- 0x00000043
    CKM_SHA384_RSA_PKCS_PSS        as Sha384RsaPkcsPss,-- 0x00000044
    CKM_SHA512_RSA_PKCS_PSS        as Sha512RsaPkcsPss,-- 0x00000045

    -- SHA-224 RSA mechanisms are new for PKCS #11 v2.20 amendment 3
    CKM_SHA224_RSA_PKCS            as Sha224RsaPkcs,-- 0x00000046
    CKM_SHA224_RSA_PKCS_PSS        as Sha224RsaPkcsPss,-- 0x00000047

    CKM_RC2_KEY_GEN                as Rc2KeyGen,-- 0x00000100
    CKM_RC2_ECB                    as Rc2Ecb,-- 0x00000101
    CKM_RC2_CBC                    as Rc2Cbc,-- 0x00000102
    CKM_RC2_MAC                    as Rc2Mac,-- 0x00000103

    -- CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0
    CKM_RC2_MAC_GENERAL            as Rc2MacGeneral,-- 0x00000104
    CKM_RC2_CBC_PAD                as Rc2CbcPad,--0x00000105

    CKM_RC4_KEY_GEN                as Rc4KeyGen,--0x00000110
    CKM_RC4                        as Rc4,--0x00000111
    CKM_DES_KEY_GEN                as DesKeyGen,--0x00000120
    CKM_DES_ECB                    as DesEcb,--0x00000121
    CKM_DES_CBC                    as DesCbc,--0x00000122
    CKM_DES_MAC                    as DesMac,--0x00000123

    -- CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0
    CKM_DES_MAC_GENERAL            as DesMacGeneral,--0x00000124
    CKM_DES_CBC_PAD                as DesCbcPad,--0x00000125

    CKM_DES2_KEY_GEN               as Des2KeyGen,--0x00000130
    CKM_DES3_KEY_GEN               as Des3KeyGen,--0x00000131
    CKM_DES3_ECB                   as Des3Ecb,--0x00000132
    CKM_DES3_CBC                   as Des3Cbc,--0x00000133
    CKM_DES3_MAC                   as Des3Mac,--0x00000134

    -- CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
    -- CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
    -- CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0
    CKM_DES3_MAC_GENERAL           as Des3MacGeneral,--0x00000135
    CKM_DES3_CBC_PAD               as Des3CbcPad,--0x00000136
    CKM_CDMF_KEY_GEN               as CdmfKeyGen,--0x00000140
    CKM_CDMF_ECB                   as CdmfEcb,--0x00000141
    CKM_CDMF_CBC                   as CdmfCbc,--0x00000142
    CKM_CDMF_MAC                   as CdmfMac,--0x00000143
    CKM_CDMF_MAC_GENERAL           as CdmfMacGeneral,--0x00000144
    CKM_CDMF_CBC_PAD               as CdmfCbcPad,--0x00000145

    -- the following four DES mechanisms are new for v2.20
    CKM_DES_OFB64                  as DesOfb64,--0x00000150
    CKM_DES_OFB8                   as DesOfb8,--0x00000151
    CKM_DES_CFB64                  as DesCfb64,--0x00000152
    CKM_DES_CFB8                   as DesCfb8,--0x00000153

    CKM_MD2                        as Md2,--0x00000200

    -- CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0
    CKM_MD2_HMAC                   as Md2Hmac,--0x00000201
    CKM_MD2_HMAC_GENERAL           as Md2HmacGeneral,--0x00000202

    CKM_MD5                        as Md5,--0x00000210

    -- CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0
    CKM_MD5_HMAC                   as Md5Hmac,--0x00000211
    CKM_MD5_HMAC_GENERAL           as Md5HmacGeneral,--0x00000212

    CKM_SHA_1                      as Sha1,--0x00000220

    -- CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0
    CKM_SHA_1_HMAC                 as Sha1Hmac,--0x00000221
    CKM_SHA_1_HMAC_GENERAL         as Sha1HmacGeneral,--0x00000222

    -- CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
    -- CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
    -- and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10
    CKM_RIPEMD128                  as RipeMd128,--0x00000230
    CKM_RIPEMD128_HMAC             as RipeMd128Hmac,--0x00000231
    CKM_RIPEMD128_HMAC_GENERAL     as RipeMd128HmacGeneral,--0x00000232
    CKM_RIPEMD160                  as Ripe160,--0x00000240
    CKM_RIPEMD160_HMAC             as Ripe160Hmac,--0x00000241
    CKM_RIPEMD160_HMAC_GENERAL     as Ripe160HmacGeneral,--0x00000242

    -- CKM_SHA256/384/512 are new for v2.20
    CKM_SHA256                     as Sha256,--0x00000250
    CKM_SHA256_HMAC                as Sha256Hmac,--0x00000251
    CKM_SHA256_HMAC_GENERAL        as Sha256HmacGeneral,--0x00000252

    -- SHA-224 is new for PKCS #11 v2.20 amendment 3
    CKM_SHA224                     as Sha224,--0x00000255
    CKM_SHA224_HMAC                as Sha224Hmac,--0x00000256
    CKM_SHA224_HMAC_GENERAL        as Sha224HmacGeneral,--0x00000257

    CKM_SHA384                     as Sha384,--0x00000260
    CKM_SHA384_HMAC                as Sha384Hmac,--0x00000261
    CKM_SHA384_HMAC_GENERAL        as Sha384HmacGeneral,--0x00000262
    CKM_SHA512                     as Sha512,--0x00000270
    CKM_SHA512_HMAC                as Sha512Hmac,--0x00000271
    CKM_SHA512_HMAC_GENERAL        as Sha512HmacGeneral,--0x00000272

    -- SecurID is new for PKCS #11 v2.20 amendment 1
    --CKM_SECURID_KEY_GEN            0x00000280
    --CKM_SECURID                    0x00000282

    -- HOTP is new for PKCS #11 v2.20 amendment 1
    --CKM_HOTP_KEY_GEN    0x00000290
    --CKM_HOTP            0x00000291

    -- ACTI is new for PKCS #11 v2.20 amendment 1
    --CKM_ACTI            0x000002A0
    --CKM_ACTI_KEY_GEN    0x000002A1

    -- All of the following mechanisms are new for v2.0
    -- Note that CAST128 and CAST5 are the same algorithm
    CKM_CAST_KEY_GEN               as CastKeyGen,--0x00000300
    CKM_CAST_ECB                   as CastEcb,--0x00000301
    CKM_CAST_CBC                   as CastCbc,--0x00000302
    CKM_CAST_MAC                   as CastMac,--0x00000303
    CKM_CAST_MAC_GENERAL           as CastMacGeneral,--0x00000304
    CKM_CAST_CBC_PAD               as CastCbcPad,--0x00000305
    CKM_CAST3_KEY_GEN              as Cast3KeyGen,--0x00000310
    CKM_CAST3_ECB                  as Cast3Ecb,--0x00000311
    CKM_CAST3_CBC                  as Cast3Cbc,--0x00000312
    CKM_CAST3_MAC                  as Cast3Mac,--0x00000313
    CKM_CAST3_MAC_GENERAL          as Cast3MacGeneral,--0x00000314
    CKM_CAST3_CBC_PAD              as Cast3CbcPad,--0x00000315
    CKM_CAST5_KEY_GEN              as Cast5KeyGen,--0x00000320
    CKM_CAST128_KEY_GEN            as Cast128KeyGen,--0x00000320
    CKM_CAST5_ECB                  as Cast5Ecb,--0x00000321
    CKM_CAST128_ECB                as Cast128Ecb,--0x00000321
    CKM_CAST5_CBC                  as Cast5Cbc,--0x00000322
    CKM_CAST128_CBC                as Cast128Cbc,--0x00000322
    CKM_CAST5_MAC                  as Cast5Mac,--0x00000323
    CKM_CAST128_MAC                as Cast128Mac,--0x00000323
    CKM_CAST5_MAC_GENERAL          as Cast5MacGeneral,--0x00000324
    CKM_CAST128_MAC_GENERAL        as Cast128MacGeneral,--0x00000324
    CKM_CAST5_CBC_PAD              as Cast5CbcPad,--0x00000325
    CKM_CAST128_CBC_PAD            as Cast128CbcPad,--0x00000325
    CKM_RC5_KEY_GEN                as Rc5KeyGen,--0x00000330
    CKM_RC5_ECB                    as Rc5Ecb,--0x00000331
    CKM_RC5_CBC                    as Rc5Cbc,--0x00000332
    CKM_RC5_MAC                    as Rc5Mac,--0x00000333
    CKM_RC5_MAC_GENERAL            as Rc5MacGeneral,--0x00000334
    CKM_RC5_CBC_PAD                as Rc5CbcPad,--0x00000335
    CKM_IDEA_KEY_GEN               as IdeaKeyGen,--0x00000340
    CKM_IDEA_ECB                   as IdeaEcb,--0x00000341
    CKM_IDEA_CBC                   as IdeaCbc,--0x00000342
    CKM_IDEA_MAC                   as IdeaMac,--0x00000343
    CKM_IDEA_MAC_GENERAL           as IdeaMacGeneral,--0x00000344
    CKM_IDEA_CBC_PAD               as IdeaCbcPad,--0x00000345
    CKM_GENERIC_SECRET_KEY_GEN     as GeneralSecretKeyGen,--0x00000350
    CKM_CONCATENATE_BASE_AND_KEY   as ConcatenateBaseAndKey,--0x00000360
    CKM_CONCATENATE_BASE_AND_DATA  as ConcatenateBaseAndData,--0x00000362
    CKM_CONCATENATE_DATA_AND_BASE  as ConcatenateDataAndBase,--0x00000363
    CKM_XOR_BASE_AND_DATA          as XorBaseAndData,--0x00000364
    CKM_EXTRACT_KEY_FROM_KEY       as ExtractKeyFromKey,--0x00000365
    CKM_SSL3_PRE_MASTER_KEY_GEN    as Ssl3PreMasterKeyGen,--0x00000370
    CKM_SSL3_MASTER_KEY_DERIVE     as Ssl3MasterKeyDerive,--0x00000371
    CKM_SSL3_KEY_AND_MAC_DERIVE    as Ssl3KeyAndMacDerive,--0x00000372

    -- CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
    -- CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
    -- CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11
    --CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
    --CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
    --CKM_TLS_MASTER_KEY_DERIVE      0x00000375
    --CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
    --CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377

    -- CKM_TLS_PRF is new for v2.20
    --CKM_TLS_PRF                    0x00000378

    --CKM_SSL3_MD5_MAC               0x00000380
    --CKM_SSL3_SHA1_MAC              0x00000381
    --CKM_MD5_KEY_DERIVATION         0x00000390
    --CKM_MD2_KEY_DERIVATION         0x00000391
    --CKM_SHA1_KEY_DERIVATION        0x00000392

    -- CKM_SHA256/384/512 are new for v2.20
    --CKM_SHA256_KEY_DERIVATION      0x00000393
    --CKM_SHA384_KEY_DERIVATION      0x00000394
    --CKM_SHA512_KEY_DERIVATION      0x00000395

    -- SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3
    CKM_SHA224_KEY_DERIVATION      as Sha224KeyDerivation,--0x00000396

    CKM_PBE_MD2_DES_CBC            as PbeMd2DesCbc,--0x000003A0
    CKM_PBE_MD5_DES_CBC            as PbeMd5DesCbc,--0x000003A1
    CKM_PBE_MD5_CAST_CBC           as PbeMd5CastCbc,--0x000003A2
    CKM_PBE_MD5_CAST3_CBC          as PbeMd5Cast3Cbc,--0x000003A3
    CKM_PBE_MD5_CAST5_CBC          as PbeMd5Cast5Cbc,--0x000003A4
    CKM_PBE_MD5_CAST128_CBC        as PbeMd5Cast128Cbc,--0x000003A4
    CKM_PBE_SHA1_CAST5_CBC         as PbeSha1Cast5Cbc,--0x000003A5
    CKM_PBE_SHA1_CAST128_CBC       as PbeSha1Cast128Cbc,--0x000003A5
    CKM_PBE_SHA1_RC4_128           as PbeSha1Rc4128,--0x000003A6
    CKM_PBE_SHA1_RC4_40            as PbeSha1Rc440,--0x000003A7
    CKM_PBE_SHA1_DES3_EDE_CBC      as PbeSha1Des3EdeCbc,--0x000003A8
    CKM_PBE_SHA1_DES2_EDE_CBC      as PbeSha1Des2EdeCbc,--0x000003A9
    CKM_PBE_SHA1_RC2_128_CBC       as PbeSha1Rc2128Cbc,--0x000003AA
    CKM_PBE_SHA1_RC2_40_CBC        as PbeSha1Rc240Cbc,--0x000003AB

    -- CKM_PKCS5_PBKD2 is new for v2.10
    CKM_PKCS5_PBKD2                as Pkcs5Pbkd2,--0x000003B0

    CKM_PBA_SHA1_WITH_SHA1_HMAC    as PbaSha1WithSha1Hmac,--0x000003C0

    -- WTLS mechanisms are new for v2.20
    --CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003D0
    --CKM_WTLS_MASTER_KEY_DERIVE          0x000003D1
    --CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003D2
    --CKM_WTLS_PRF                        0x000003D3
    --CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003D4
    --CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003D5

    --CKM_KEY_WRAP_LYNKS             0x00000400
    --CKM_KEY_WRAP_SET_OAEP          0x00000401

    -- CKM_CMS_SIG is new for v2.20
    --CKM_CMS_SIG                    0x00000500

    -- CKM_KIP mechanisms are new for PKCS #11 v2.20 amendment 2
    --CKM_KIP_DERIVE	               0x00000510
    --CKM_KIP_WRAP	               0x00000511
    --CKM_KIP_MAC	               0x00000512

    -- Camellia is new for PKCS #11 v2.20 amendment 3
    --CKM_CAMELLIA_KEY_GEN           0x00000550
    --CKM_CAMELLIA_ECB               0x00000551
    --CKM_CAMELLIA_CBC               0x00000552
    --CKM_CAMELLIA_MAC               0x00000553
    --CKM_CAMELLIA_MAC_GENERAL       0x00000554
    --CKM_CAMELLIA_CBC_PAD           0x00000555
    --CKM_CAMELLIA_ECB_ENCRYPT_DATA  0x00000556
    --CKM_CAMELLIA_CBC_ENCRYPT_DATA  0x00000557
    --CKM_CAMELLIA_CTR               0x00000558

    -- ARIA is new for PKCS #11 v2.20 amendment 3
    --CKM_ARIA_KEY_GEN               0x00000560
    --CKM_ARIA_ECB                   0x00000561
    --CKM_ARIA_CBC                   0x00000562
    --CKM_ARIA_MAC                   0x00000563
    --CKM_ARIA_MAC_GENERAL           0x00000564
    --CKM_ARIA_CBC_PAD               0x00000565
    --CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566
    --CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567

    -- Fortezza mechanisms
    --CKM_SKIPJACK_KEY_GEN           0x00001000
    --CKM_SKIPJACK_ECB64             0x00001001
    --CKM_SKIPJACK_CBC64             0x00001002
    --CKM_SKIPJACK_OFB64             0x00001003
    --CKM_SKIPJACK_CFB64             0x00001004
    --CKM_SKIPJACK_CFB32             0x00001005
    --CKM_SKIPJACK_CFB16             0x00001006
    --CKM_SKIPJACK_CFB8              0x00001007
    --CKM_SKIPJACK_WRAP              0x00001008
    --CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
    --CKM_SKIPJACK_RELAYX            0x0000100a
    --CKM_KEA_KEY_PAIR_GEN           0x00001010
    --CKM_KEA_KEY_DERIVE             0x00001011
    --CKM_FORTEZZA_TIMESTAMP         0x00001020
    --CKM_BATON_KEY_GEN              0x00001030
    --CKM_BATON_ECB128               0x00001031
    --CKM_BATON_ECB96                0x00001032
    --CKM_BATON_CBC128               0x00001033
    --CKM_BATON_COUNTER              0x00001034
    --CKM_BATON_SHUFFLE              0x00001035
    --CKM_BATON_WRAP                 0x00001036

    -- CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
    -- CKM_EC_KEY_PAIR_GEN is preferred
    CKM_ECDSA_KEY_PAIR_GEN         as EcdsaKeyPairGen,--0x00001040
    CKM_EC_KEY_PAIR_GEN            as EcKeyPairGen,--0x00001040

    CKM_ECDSA                      as Ecdsa,--0x00001041
    CKM_ECDSA_SHA1                 as EcdsaSha1,--0x00001042

    -- CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
    -- are new for v2.11
    CKM_ECDH1_DERIVE               as Ecdh1Derive,--0x00001050
    CKM_ECDH1_COFACTOR_DERIVE      as Ecdh1CofactorDerive,--0x00001051
    CKM_ECMQV_DERIVE               as DcmqvDerive,--0x00001052

    CKM_JUNIPER_KEY_GEN            as JuniperKeyGen,--0x00001060
    CKM_JUNIPER_ECB128             as JuniperEcb128,--0x00001061
    CKM_JUNIPER_CBC128             as JuniperCbc128,--0x00001062
    CKM_JUNIPER_COUNTER            as JuniperCounter,--0x00001063
    CKM_JUNIPER_SHUFFLE            as JuniperShuffle,--0x00001064
    CKM_JUNIPER_WRAP               as JuniperWrap,--0x00001065
    CKM_FASTHASH                   as FastHash,--0x00001070

    -- CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
    -- CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
    -- CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
    -- new for v2.11
    CKM_AES_KEY_GEN                as AesKeyGen,--0x00001080
    CKM_AES_ECB                    as AesEcb,
    CKM_AES_CBC                    as AesCbc,
    CKM_AES_MAC                    as AesMac,
    CKM_AES_MAC_GENERAL            as AesMacGeneral,
    CKM_AES_CBC_PAD                as AesCbcPad,

    -- AES counter mode is new for PKCS #11 v2.20 amendment 3
    CKM_AES_CTR                    as AesCtr,

    CKM_AES_GCM                    as AesGcm,--0x00001087
    CKM_AES_CCM                    as AesCcm,--0x00001088
    CKM_AES_KEY_WRAP               as AesKeyWrap,--0x00001090
    CKM_AES_KEY_WRAP_PAD           as AesKeyWrapPad,--0x00001091

    -- BlowFish and TwoFish are new for v2.20
    CKM_BLOWFISH_KEY_GEN           as BlowfishKeyGen,
    CKM_BLOWFISH_CBC               as BlowfishCbc,
    CKM_TWOFISH_KEY_GEN            as TwoFishKeyGen,
    CKM_TWOFISH_CBC                as TwoFishCbc,

    -- CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20
    CKM_DES_ECB_ENCRYPT_DATA       as DesEcbEncryptData,
    CKM_DES_CBC_ENCRYPT_DATA       as DesCbcEncryptData,
    CKM_DES3_ECB_ENCRYPT_DATA      as Des3EcbEncryptData,
    CKM_DES3_CBC_ENCRYPT_DATA      as Des3CbcEncryptData,
    CKM_AES_ECB_ENCRYPT_DATA       as AesEcbEncryptData,
    CKM_AES_CBC_ENCRYPT_DATA       as AesCbcEncryptData,

    CKM_DSA_PARAMETER_GEN as DsaParameterGen,
    CKM_DH_PKCS_PARAMETER_GEN      as DhPkcsParameterGen,
    CKM_X9_42_DH_PARAMETER_GEN     as X9_42DhParameterGen,

    CKM_VENDOR_DEFINED             as VendorDefined
    } deriving (Eq,Show) #}


{#enum define ReturnValue {
    CKR_OK as CKR_OK,
    CKR_CANCEL as CKR_CANCEL,
    CKR_MECHANISM_INVALID as CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID as CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_ACTIVE as CKR_OPERATION_ACTIVE,
    CKR_BUFFER_TOO_SMALL as CKR_BUFFER_TOO_SMALL
} deriving (Eq, Show) #}

toRv :: ReturnValue -> CK_RV
toRv rv = fromIntegral $ fromEnum rv
