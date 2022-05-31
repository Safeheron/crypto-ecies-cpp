/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#include "ecies.h"
#include "kdf.h"
#include "symm.h"
#include "hmac.h"
#include <assert.h>
#include <crypto-bn/rand.h>
#include <crypto-curve/curve.h>

using namespace safeheron;

namespace curve {
namespace enc {

ECIES::ECIES() { 
    curve_type_ = CurveType::P256; 

    // in default
    //hash_alg_ = HASHAlg::SHA512;
    //symm_key_size_ = 256;
    //mac_key_size_ = 128;

    // We use the following setting in default:
    // KDF: KDF_X9_63_SHA512
    // Symmetic: AES256_CBC
    // MAC: HMAC_SHA512
    kdf_ = new KDF_X9_63(NID_sha512);
    symm_ = new AES(256);
    hmac_ = new HMAC_sha512();
    symm_alg_ = SYMM_ALG::AES256_CBC;

    assert(kdf_ != nullptr);
    assert(symm_ != nullptr);
    assert(hmac_ != nullptr);
}
ECIES::~ECIES() {
    free();
}

// Release all interface objects
void ECIES::free() {
    //symm_key_size_ = 0;
    //mac_key_size_ = 0;
    //hash_alg_ = HASHAlg::INVALID_ALG;
    //ecies_alg_ = ECIESAlg::INVALID_ALG;
    symm_alg_ = SYMM_ALG::INVALID_ALG;

    if (kdf_) {
        delete kdf_;
        kdf_ = nullptr;
    }
    if (symm_) {
        delete symm_;
        symm_ = nullptr;
    }
    if (hmac_) {
        delete hmac_;
        hmac_ = nullptr;
    }
}

void ECIES::set_curve_type(CurveType curve_type) {
    curve_type_ = curve_type;
}
#if 0
bool ECIES::Encrypt(const CurvePoint &pub, const unsigned char *in_plain, size_t in_plain_len,
                            unsigned char **out_cypher, size_t *out_cypher_len) {
    const Curve *curv = curve::GetCurveParam(curve_type_);
    if (curv == nullptr) return false;

    uint8_t xy[65];
    SHA512_CTX ctx;
    aes_encrypt_ctx ctxe;
    HMAC_SHA512_CTX hctx;
    uint8_t text[256];
    uint8_t *aes_in_buf;
    uint8_t *aes_out_buf;
    uint8_t pad;
    uint8_t padlen;
    size_t pplen;

    uint8_t digest[64];
    uint8_t T[64];
    uint8_t C[4] = {0};
    uint8_t test[8] = {0};
    uint8_t share[33] = {0};

    uint8_t K1[32] = {0};
    uint8_t K2[16] = {0};

    uint8_t iv[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (!pub.IsValid() || pub.IsInfinity() || in_plain == nullptr || out_cypher == nullptr ||
        in_plain_len == 0)
        return false;

    // ECDH for the key( K1, K2 )
    CurvePoint G1, G2;
    ntl::BN ephemeral_key;
    do {
        ephemeral_key = Rand::RandomBNLtGcd(curv->n);
        G1 = curv->g * ephemeral_key;
        G2 = pub * ephemeral_key;
    }while (G2.IsInfinity());

    G1.EncodeFull(xy);
    G2.EncodeCompressed(share);

    sha512_Init(&ctx);
    sha512_Update(&ctx, xy, 65);
    sha512_Update(&ctx, share + 1, 32);
    sha512_Update(&ctx, C, 4);
    sha512_Final(&ctx, digest);

    memcpy(K1, digest, 32);
    memcpy(K2, digest + 32, 16);

    // aes encryption
    aes_encrypt_key256(K1, &ctxe);
    pad = in_plain_len % 16;
    padlen = 16 - pad;
    pplen = in_plain_len + padlen;
    aes_in_buf = (uint8_t *) malloc(pplen);
    if (aes_in_buf == nullptr)
        return false;
    aes_out_buf = (uint8_t *) malloc(pplen);
    if (aes_out_buf == nullptr) {
        free(aes_in_buf);
        return false;
    }
    memcpy(aes_in_buf, in_plain, in_plain_len);
    memset(aes_in_buf + in_plain_len, padlen, padlen);
    aes_cbc_encrypt(aes_in_buf, aes_out_buf, pplen, iv, &ctxe);

    // hmac
    hmac_sha512_Init(&hctx, K2, 16);
    hmac_sha512_Update(&hctx, aes_out_buf, pplen);
    hmac_sha512_Update(&hctx, test, 8);
    hmac_sha512_Final(&hctx, T);

    *out_cypher_len = pplen + 65 + 64;
    *out_cypher = (unsigned char *)malloc(*out_cypher_len);
    if(*out_cypher == nullptr){
        free(aes_in_buf);
        free(aes_out_buf);
        return false;
    }

    memcpy(*out_cypher, xy, 65);
    memcpy(*out_cypher + 65, aes_out_buf, pplen);
    memcpy(*out_cypher + 65 + pplen, T, 64);

    free(aes_in_buf);
    free(aes_out_buf);

    return true;
}

bool ECIES::Decrypt(const ntl::BN &priv, const unsigned char *in_cypher, size_t in_cypher_len, unsigned char **out_plain,
                            size_t *out_plain_len) {
    const Curve *curv = curve::GetCurveParam(curve_type_);
    if (curv == nullptr) return false;

    SHA512_CTX ctx;
    int istrue;
    bool ok = true;
    uint8_t text[256];
    aes_decrypt_ctx ctxd;
    HMAC_SHA512_CTX hctx;
    uint8_t digest[64];
    uint8_t T[64];
    uint8_t C[4] = {0};
    uint8_t test[8] = {0};
    uint8_t share[33] = {0};
    CurvePoint G;
    size_t aeslen, aestruelen;
    uint8_t xy[65];
    uint8_t K1[32] = {0};
    uint8_t K2[16] = {0};
    uint8_t crypt[48];
    uint8_t iv[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    aeslen = in_cypher_len - 65 - 64;

    if (priv == 0 || out_plain == nullptr || in_cypher == nullptr || in_cypher_len == 0)
        return false;

    // ECDH for the key( K1, K2 )
    ok = G.DecodeFull(in_cypher, curve_type_);
    if (!ok) return false;
    G.EncodeFull(xy);
    G = G * priv;

    G.EncodeCompressed(share);

    sha512_Init(&ctx);
    sha512_Update(&ctx, xy, 65);
    sha512_Update(&ctx, share + 1, 32);
    sha512_Update(&ctx, C, 4);
    sha512_Final(&ctx, digest);

    memcpy(K1, digest, 32);
    memcpy(K2, digest + 32, 16);

    hmac_sha512_Init(&hctx, K2, 16);
    hmac_sha512_Update(&hctx, in_cypher + 65, aeslen);
    hmac_sha512_Update(&hctx, test, 8);
    hmac_sha512_Final(&hctx, T);
    istrue = memcmp(T, in_cypher + 65 + aeslen, 64);
    if (istrue != 0) {
        return false;
    }

    *out_plain = (unsigned char *)malloc(in_cypher_len);
    aes_decrypt_key256(K1, &ctxd);
    aes_cbc_decrypt(in_cypher + 65, *out_plain, aeslen, (unsigned char *) iv, &ctxd);
    *out_plain_len = aeslen - (*out_plain)[aeslen - 1];

    return true;
}

bool ECIES::Encrypt(const CurvePoint &pub, const std::string &in_plain, std::string &out_cypher){
    unsigned char *t_cypher = nullptr;
    size_t t_cypher_len = 0;
    bool ok = Encrypt(pub, (const unsigned char *)in_plain.c_str(), in_plain.length(), &t_cypher, &t_cypher_len);
    if(!ok) return false;
    out_cypher.assign((char *)t_cypher, t_cypher_len);
    free(t_cypher);
    return true;
}

bool ECIES::Decrypt(const ntl::BN &priv, const std::string &in_cypher, std::string &out_plain){
    unsigned char *t_plain = nullptr;
    size_t t_plain_len = 0;
    bool ok = Decrypt(priv, (const unsigned char *)in_cypher.c_str(), in_cypher.length(), &t_plain, &t_plain_len);
    if(!ok) return false;
    out_plain.assign((char *)t_plain, t_plain_len);
    free(t_plain);
    return true;
}
#endif //0


#if 0
// Set ecies algorithm
// If this API is not called, we use ECIESwithSHA512andAESCBC in default.
//
// alg: one of ECIESAlg value.
bool ECIES::set_ecies_alg(const ECIESAlg alg) {
    if (ECIESAlg::INVALID_ALG == alg) {
        return false;
    }
    ecies_alg_ = alg;

    // free old interfaces
    free();

    // set the default symmetic key size and mac key size for ecies_alg
    switch (ecies_alg_)
    {
    case ECIESAlg::ECIESwithDESedeCBC:
        hash_alg_ = HASHAlg::SHA1;
        kdf_ = new KDF1_18033(NID_sha1);
        symm_ = new DESede();
        hmac_ = new HMAC_sha1();
        symm_key_size_ = 24*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA256andDESedeCBC:
        hash_alg_ = HASHAlg::SHA256;
        kdf_ = new KDF1_18033(NID_sha256);
        symm_ = new DESede();
        hmac_ = new HMAC_sha2(256);
        symm_key_size_ = 24*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA384andDESedeCBC:
        hash_alg_ = HASHAlg::SHA384;
        kdf_ = new KDF1_18033(NID_sha384);
        symm_ = new DESede();
        hmac_ = new HMAC_sha2(384);
        symm_key_size_ = 24*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA512andDESedeCBC:
        hash_alg_ = HASHAlg::SHA512;
        kdf_ = new KDF1_18033(NID_sha512);
        symm_ = new DESede();
        hmac_ = new HMAC_sha2(512);
        symm_key_size_ = 24*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithAESCBC:
        hash_alg_ = HASHAlg::SHA1;
        kdf_ = new KDF1_18033(NID_sha1);
        symm_ = new AES();
        hmac_ = new HMAC_sha1();
        symm_key_size_ = 32*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA256andAESCBC:
        hash_alg_ = HASHAlg::SHA256;
        kdf_ = new KDF1_18033(NID_sha256);
        symm_ = new AES();
        hmac_ = new HMAC_sha2(256);
        symm_key_size_ = 32*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA384andAESCBC:
        hash_alg_ = HASHAlg::SHA384;
        kdf_ = new KDF1_18033(NID_sha384);
        symm_ = new AES();
        hmac_ = new HMAC_sha2(384);
        symm_key_size_ = 32*8;
        mac_key_size_ = 128;
        break;
    case ECIESAlg::ECIESwithSHA512andAESCBC:
        hash_alg_ = HASHAlg::SHA512;
        kdf_ = new KDF1_18033(NID_sha512);
        symm_ = new AES();
        hmac_ = new HMAC_sha2(512);
        symm_key_size_ = 32*8;
        mac_key_size_ = 128;
        break;
    default:
        return false;
    }

    assert(kdf_ != nullptr);
    assert(symm_ != nullptr);
    assert(hmac_ != nullptr);
    return true;
}

// Return current ecies algorithm in using
ECIESAlg ECIES::get_ecies_alg() {
    return ecies_alg_;
}

// Set symmetic key size and MAC key size in ecies
// If this API is not called, we use 192 for DESede and 256 for AES.
//
// aes_key_size: the AES key size, should be 128,192 or 265.
// mac_key_size: the MAC key size, it is 128 in default.
bool ECIES::set_key_size(const int aes_key_size, const int mac_key_size) {
    if ( 128 != aes_key_size && 192 != aes_key_size && 256 != aes_key_size ) {
        return false;
    }

    // aes_key_size only can be set for AES
    if (ecies_alg_ == ECIESAlg::ECIESwithAESCBC ||
        ecies_alg_ == ECIESAlg::ECIESwithSHA256andAESCBC ||
        ecies_alg_ == ECIESAlg::ECIESwithSHA384andAESCBC ||
        ecies_alg_ == ECIESAlg::ECIESwithSHA512andAESCBC) {
        if ( 128 != aes_key_size && 192 != aes_key_size && 256 != aes_key_size ) {
            return false;
        }
        symm_key_size_ = aes_key_size;
    }

    if (mac_key_size > MAX_HMAC_KEY_LEN) {
        return false;
    }
    mac_key_size_ = mac_key_size;

    return true;
}

// Return the symmetic key size and mac key size, in bits
void ECIES::get_key_size(int & symm_key_size, int & mac_key_size) {
    symm_key_size = symm_key_size_;
    mac_key_size = mac_key_size_;
}
#endif //0


// Set symmetic algorithm using in ECIE
// If this API is not called, we use AES256_CBC in default.
//
// alg: one of SYMM_ALG value.
bool ECIES::set_symm_alg(SYMM_ALG alg) {
    if (alg == SYMM_ALG::INVALID_ALG) {
        return false;
    }

    // free old interface object
    if (symm_) {
        delete symm_;
        symm_ = nullptr;
    }
    symm_alg_ = alg;

    // create new object for symmetic
    switch(symm_alg_) 
    {
    case SYMM_ALG::DESede_CBC:
        symm_ = new DESede();
        break;
    case SYMM_ALG::AES128_CBC:
        symm_ = new AES(128);
        break;
    case SYMM_ALG::AES192_CBC:
        symm_ = new AES(192);
        break;
    case SYMM_ALG::AES256_CBC:
        symm_ = new AES(256);
        break;
    default:
        symm_alg_ = SYMM_ALG::INVALID_ALG;
        return false;
    }

    assert(symm_);

    return true;
}

// Return current symmetic algorithm in using currently
SYMM_ALG ECIES::get_symm_alg() {
    return symm_alg_;
}

// Set key derivation function type
// If this API is not called, we use KDF1_18033_SHA512 in default.
//
// kdf: KDF type, should be one of KDF_TYPE.
bool ECIES::set_kdf_type(KDF_TYPE kdf) {
    if (KDF_TYPE::INVALID_TYPE == kdf) {
        return false;
    }

    // free old interface object
    if (kdf_) {
        delete kdf_;
        kdf_ = nullptr;
    }
    
    // construct the new interface object
    switch (kdf)
    {
    case KDF_TYPE::KDF_X9_63_With_SHA1:
        kdf_ = new KDF_X9_63(NID_sha1);
        break;
    case KDF_TYPE::KDF_X9_63_With_SHA256:
        kdf_ = new KDF_X9_63(NID_sha256);
        break;
    case KDF_TYPE::KDF_X9_63_With_SHA384:
        kdf_ = new KDF_X9_63(NID_sha384);
        break;
    case KDF_TYPE::KDF_X9_63_With_SHA512:
        kdf_ = new KDF_X9_63(NID_sha512);
        break;
    case KDF_TYPE::KDF1_18033_With_SHA1:
        kdf_ = new KDF1_18033(NID_sha1);
        break;
    case KDF_TYPE::KDF1_18033_With_SHA256:
        kdf_ = new KDF1_18033(NID_sha256);
        break;
    case KDF_TYPE::KDF1_18033_With_SHA384:
        kdf_ = new KDF1_18033(NID_sha384);
        break;
    case KDF_TYPE::KDF1_18033_With_SHA512:
        kdf_ = new KDF1_18033(NID_sha512);
        break;
    case KDF_TYPE::KDF2_18033_With_SHA1:
        kdf_ = new KDF2_18033(NID_sha1);
        break;
    case KDF_TYPE::KDF2_18033_With_SHA256:
        kdf_ = new KDF2_18033(NID_sha256);
        break;
    case KDF_TYPE::KDF2_18033_With_SHA384:
        kdf_ = new KDF2_18033(NID_sha384);
        break;
    case KDF_TYPE::KDF2_18033_With_SHA512:
        kdf_ = new KDF2_18033(NID_sha512);
        break;
    default:
        return false;
    }

    assert(kdf_ != nullptr);

    return true;
}

// Return the KDF type is using currently
KDF_TYPE ECIES::ECIES::get_kdf_type() {
    assert(kdf_);

    int nid = kdf_->getHashNid();
    const char* class_name = typeid(kdf_).name();
    if (memcmp(class_name, "KDF_X9_63", strlen("KDF_X9_63")) == 0) {
        if (nid == NID_sha1)
            return KDF_TYPE::KDF_X9_63_With_SHA1;
        else if (nid == NID_sha256)
            return KDF_TYPE::KDF_X9_63_With_SHA256;
        else if (nid == NID_sha384)
            return KDF_TYPE::KDF_X9_63_With_SHA384;
        else if (nid == NID_sha512)
            return KDF_TYPE::KDF_X9_63_With_SHA512;
        else
            return KDF_TYPE::INVALID_TYPE;
    }
    else if (memcmp(class_name, "KDF1_18033", strlen("KDF1_18033")) == 0) {
        if (nid == NID_sha1)
            return KDF_TYPE::KDF1_18033_With_SHA1;
        else if (nid == NID_sha256)
            return KDF_TYPE::KDF1_18033_With_SHA256;
        else if (nid == NID_sha384)
            return KDF_TYPE::KDF1_18033_With_SHA384;
        else if (nid == NID_sha512)
            return KDF_TYPE::KDF1_18033_With_SHA512;
        else
            return KDF_TYPE::INVALID_TYPE;
    }
    else if (memcmp(class_name, "KDF2_18033", strlen("KDF2_18033")) == 0) {
        if (nid == NID_sha1)
            return KDF_TYPE::KDF2_18033_With_SHA1;
        else if (nid == NID_sha256)
            return KDF_TYPE::KDF2_18033_With_SHA256;
        else if (nid == NID_sha384)
            return KDF_TYPE::KDF2_18033_With_SHA384;
        else if (nid == NID_sha512)
            return KDF_TYPE::KDF2_18033_With_SHA512;
        else
            return KDF_TYPE::INVALID_TYPE;
    }
    
    return KDF_TYPE::INVALID_TYPE;
}

// Set HMAC algorithm type
// If this API is not called, we use HMAC_SHA512 in default.
//
// hash: Hash algorithm used in HMAC, should be one of HMAC_ALG.
bool ECIES::set_mac_type(HMAC_ALG mac) {
    if (HMAC_ALG::INVALID_ALG == mac) {
        return false;
    }

    // free old interface object
    if (hmac_) {
        delete hmac_;
        hmac_ = nullptr;
    }
    
    // construct the new interface object
    switch (mac)
    {
    case HMAC_ALG::HMAC_SHA1:
        hmac_ = new HMAC_sha1();
        break;
    case HMAC_ALG::HMAC_SHA256:
        hmac_ = new HMAC_sha256();
        break;
    case HMAC_ALG::HMAC_SHA384:
        hmac_ = new HMAC_sha384();
        break;
    case HMAC_ALG::HMAC_SHA512:
        hmac_ = new HMAC_sha512();
        break;
    default:
        return false;
    }

    assert(hmac_ != nullptr);

    return true;
}

// Return the HMAC type is using currently
HMAC_ALG ECIES::get_mac_type() {
    assert(hmac_ != nullptr);

    const char* class_name = typeid(kdf_).name();
    if (memcmp(class_name, "HMAC_sha1", strlen("HMAC_sha1")) == 0) {
        return HMAC_ALG::HMAC_SHA1;
    }
    else if (memcmp(class_name, "HMAC_sha256", strlen("HMAC_sha256")) == 0) {
        return HMAC_ALG::HMAC_SHA256;
    }
    else if (memcmp(class_name, "HMAC_sha384", strlen("HMAC_sha384")) == 0) {
        return HMAC_ALG::HMAC_SHA384;
    }
    else if (memcmp(class_name, "HMAC_sha512", strlen("HMAC_sha512")) == 0) {
        return HMAC_ALG::HMAC_SHA512;
    }
    else {
        return HMAC_ALG::INVALID_ALG;
    }

}

// Set derivation IV (salt) for KDF_X9_63 only, null in default.
// This API takes no effect on KDF1 and KDF2.
//
// iv: IV bytes
// len: IV length, in bytes
bool ECIES::set_derivation_iv(const unsigned char* iv, const size_t len) {
    assert(kdf_);

    if (len > MAX_SALT_IV_LEN) {
        return false;
    }

    std::string in_iv;
    if (iv && len > 0) {
        in_iv.assign((const char*)iv, len);
    }
    kdf_->setIV(in_iv);
    return true;
}

// Return the derivation IV data which is using in current KDF.
void ECIES::get_derivation_iv(std::string & out_iv) {
    assert(kdf_);
    kdf_->getIV(out_iv);
}

// Set encoding IV for HMAC
// If this API is not called, we use null in default.
//
// iv: IV bytes
// len: IV length, in bytes
bool ECIES::set_mac_iv(const unsigned char* iv, const size_t len) {
    assert(hmac_);

    if (len > MAX_SALT_IV_LEN) {
        return false;
    }

    std::string in_iv;
    if (iv && len > 0) {
        in_iv.assign((const char*)iv, len);
    }
    hmac_->setIV(in_iv);
    return true;
}

// Return the encoding IV data which is using in current HMAC.
void ECIES::get_mac_iv(std::string & out_iv) {
    assert(hmac_);
    hmac_->getIV(out_iv);
}

// Encrypt and decrypt
// out_cypher is in format: 0x04|x|y|c|h
bool ECIES::EncryptWithIV(const CurvePoint &pubkey, 
                          const std::string &in_plain, 
                          const std::string &in_iv, 
                          std::string &out_cypher) {
    return EncryptWithIV(pubkey, (const unsigned char*)in_plain.c_str(), in_plain.length(),
                         (const unsigned char*)in_iv.c_str(), in_iv.length(), out_cypher);
}
bool ECIES::Encrypt(const CurvePoint &pubkey, 
                    const std::string &in_plain, 
                    std::string &out_iv, 
                    std::string &out_cypher) {
    int iv_len = 0;
    uint8_t iv[MAX_CBC_IV_LEN] = {0};

    assert(symm_);

    // generate a rand number as the CBC IV
    iv_len = (symm_->getIVSize() + 7) / 8;
    if (iv_len > MAX_CBC_IV_LEN) {
        return false;
    }
    safeheron::rand::RandomBytes(iv, iv_len);
    out_iv.assign((const char*)iv, iv_len);

    return EncryptWithIV(pubkey, in_plain, out_iv, out_cypher);
}
bool ECIES::Decrypt(const BN &privkey, 
                    const std::string &in_cypher, 
                    const std::string &in_iv, 
                    std::string &out_plain) {
    return Decrypt(privkey, (const unsigned char*)in_cypher.c_str(), in_cypher.length(), 
                   (const unsigned char*)in_iv.c_str(), in_iv.length(), out_plain);
}
//
bool ECIES::EncryptWithIV(const CurvePoint &pubkey, 
                          const unsigned char *in_plain, size_t in_plain_len, 
                          const unsigned char *in_iv, size_t in_iv_len, 
                          std::string &out_cypher) {
    int symm_key_size = 0;
    int mac_key_size = 0;
    uint8_t xy[65] = { 0 };
    uint8_t share[33] = { 0 };
    const Curve *curv = GetCurveParam(curve_type_);
    if (curv == nullptr) return false;

    // checking status
    assert(kdf_);
    assert(symm_);
    assert(hmac_);
    symm_key_size = (symm_->getKeySize() + 7) / 8;
    mac_key_size = (hmac_->getBlockSize() + 7) / 8;
    if (symm_key_size <= 0 || mac_key_size <= 0) {
        return false;
    }

    // checking input
    if (!pubkey.IsValid() || pubkey.IsInfinity()) {
        return false;
    }
    if (!in_plain || in_plain_len <= 0) {
        return false;
    }
    if (!in_iv || in_iv_len <= 0) {
        return false;
    }
    if (in_plain_len > MAX_INPUT_DATA_LEN) {
        return false;
    }
    if (in_iv_len > MAX_CBC_IV_LEN) {
        return false;
    }

    // ECDH for the key( K1, K2 )
    CurvePoint G1, G2;
    BN ephemeral_key;
    do {
        ephemeral_key = rand::RandomBNLtGcd(curv->n);
        G1 = curv->g * ephemeral_key;
        G2 = pubkey * ephemeral_key;
    }while (G2.IsInfinity());
    G1.EncodeFull(xy);
    G2.EncodeCompressed(share);

    // derivate symm key and hmac key
    std::string k1k2;
    std::string seed;
    seed.append((const char*)xy, 65);
    seed.append((const char*)(share + 1), 32);
    if (!kdf_->generateBytes(seed, symm_key_size+mac_key_size, k1k2)) {
        return false;
    }

    // encrypt in_plain with symmetic algorithm
    std::string cbc_iv;
    std::string cypher;
    std::string k1 = k1k2.substr(0, symm_key_size);
    cbc_iv.assign((const char*)in_iv, in_iv_len);
    if (!symm_->initKey_CBC(k1, cbc_iv)) {
        return false;
    }
    if (!symm_->encrypt(in_plain, in_plain_len, cypher)) {
        return false;
    }

    // calc HMAC for cypher
    std::string mac;
    std::string k2 = k1k2.substr(symm_key_size, mac_key_size);
    if (!hmac_->calcMAC(k2, cypher, mac)) {
        return false;
    }

    // return result
    out_cypher.append((const char*)xy, 65);
    out_cypher.append(cypher);
    out_cypher.append(mac);
    return true;
}

bool ECIES::Encrypt(const CurvePoint &pubkey, 
                    const unsigned char *in_plain, size_t in_plain_len, 
                    std::string &out_iv, 
                    std::string &out_cypher) {
    if (!in_plain || in_plain_len <= 0) {
        return false;
    }
    if (in_plain_len > MAX_INPUT_DATA_LEN) {
        return false;
    }

    std::string plain;
    plain.assign((const char*)in_plain, in_plain_len);
    return Encrypt(pubkey, plain, out_iv, out_cypher);
}

bool ECIES::Decrypt(const BN &privkey, 
                    const unsigned char *in_cypher, size_t in_cypher_len, 
                    const unsigned char *in_iv, size_t in_iv_len, 
                    std::string &out_plain) {
    CurvePoint G;
    int symm_key_size = 0;
    int mac_key_size = 0;
    uint8_t xy[65] = {0};
    uint8_t share[33] = {0};
    const Curve *curv = GetCurveParam(curve_type_);
    if (curv == nullptr) return false;

    // checking status
    assert(kdf_);
    assert(symm_);
    assert(hmac_);
    symm_key_size = (symm_->getKeySize() + 7) / 8;
    mac_key_size = (hmac_->getBlockSize() + 7) / 8;
    if (symm_key_size <= 0 || mac_key_size <= 0) {
        return false;
    }

    // checking input
    if (!in_cypher || in_cypher_len <= (65+24)) {
        return false;
    }
    if (!in_iv || in_iv_len <= 0) {
        return false;
    }
    if (in_cypher_len > MAX_INPUT_DATA_LEN) {
        return false;
    }
    if (in_iv_len > MAX_CBC_IV_LEN) {
        return false;
    }

    // ECDH for the key( K1, K2 )
    if (!G.DecodeFull(in_cypher, curve_type_)) {
        return false;
    }
    G.EncodeFull(xy);
    G = G * privkey;
    G.EncodeCompressed(share);

    // derivate symm key and hmac key
    std::string k1k2;
    std::string seed;
    seed.append((const char*)xy, 65);
    seed.append((const char*)(share + 1), 32);
    if (!kdf_->generateBytes(seed, symm_key_size+mac_key_size, k1k2)) {
        return false;
    }

    // calc HMAC for cypher
    std::string mac;
    std::string symm_cypher;
    std::string k2 = k1k2.substr(symm_key_size, mac_key_size);
    int symm_cypher_len = in_cypher_len - (65 + hmac_->getOutSize()/8);
    symm_cypher.assign((const char*)(in_cypher+65), symm_cypher_len);
    if (!hmac_->calcMAC(k2, symm_cypher, mac)) {
        return false;
    }

    // checking HMAC
    std::string in_mac;
    in_mac.assign((const char*)(in_cypher+65+symm_cypher_len), hmac_->getOutSize()/8);
    if (memcmp(in_mac.c_str(), mac.c_str(), mac.length()) != 0) {
        return false;
    }

    // decrypt cypher use symmetic algorithm
    std::string cbc_iv;
    std::string k1 = k1k2.substr(0, symm_key_size);
    cbc_iv.assign((const char*)in_iv, in_iv_len);
    if (!symm_->initKey_CBC(k1, cbc_iv)) {
        return false;
    }
    if (!symm_->decrypt(symm_cypher, out_plain)) {
        return false;
    }

    return true;
}

// Encrypt pack and decrypt pack
// out_cypher is in format: 0x04|x|y|c|h|iv, iv is 8 bytes for DESede, and 16 bytes for AES
bool ECIES::EncryptPackWithIV(const CurvePoint &pubkey, 
                              const std::string &in_plain, 
                              const std::string &in_iv, 
                              std::string &out_cypher) {
    return EncryptWithIV(pubkey, (const unsigned char*)in_plain.c_str(), in_plain.length(),
                         (const unsigned char*)in_iv.c_str(), in_iv.length(), out_cypher);
}

bool ECIES::EncryptPack(const CurvePoint &pubkey, 
                        const std::string &in_plain, 
                        std::string &out_cypher) {

    return EncryptPack(pubkey, (const unsigned char*)in_plain.c_str(), in_plain.length(), out_cypher);
}

bool ECIES::DecryptPack(const BN &privkey, 
                        const std::string &in_cypher, 
                        std::string &out_plain) {
    return DecryptPack(privkey, (const unsigned char*)in_cypher.c_str(), in_cypher.length(), out_plain);
}
//
bool ECIES::EncryptPackWithIV(const CurvePoint &pubkey, 
                              const unsigned char *in_plain, size_t in_plain_len, 
                              const unsigned char *in_iv, size_t in_iv_len, 
                              std::string &out_cypher) {
    assert(symm_);

    if (!EncryptWithIV(pubkey, in_plain, in_plain_len, in_iv, in_iv_len, out_cypher)) {
        return false;
    }

    // packing iv in the end of ecies cypher
    int iv_len = (symm_->getIVSize() + 7) / 8;
    out_cypher.append((const char*)in_iv, iv_len);

    return true;
}

bool ECIES::EncryptPack(const CurvePoint &pubkey, 
                        const unsigned char *in_plain, size_t in_plain_len, 
                        std::string &out_cypher){
    assert(symm_);

    std::string out_iv;
    if (!Encrypt(pubkey, in_plain, in_plain_len, out_iv, out_cypher)) {
        return false;
    }

    // packing iv in the end of ecies cypher
    int iv_len = (symm_->getIVSize() + 7) / 8;
    out_cypher.append(out_iv.c_str(), iv_len);

    return true;
}

bool ECIES::DecryptPack(const BN &privkey, 
                        const unsigned char *in_cypher, size_t in_cypher_len,
                        std::string &out_plain) {
    assert(symm_);

    int iv_len = (symm_->getIVSize() + 7) / 8;
    return Decrypt(privkey, in_cypher, in_cypher_len-iv_len, 
                 in_cypher + (in_cypher_len-iv_len), iv_len, out_plain);
}


}
}
