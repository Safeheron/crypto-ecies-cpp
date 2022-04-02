//
// Created by 何剑虹 on 2021/10/8.
//

#include "ecies.h"
#include "../../3rdparty/crypto/aes/aes.h"
#include "../../3rdparty/crypto/hmac.h"
#include "../../3rdparty/hex/hex_conv.h"
#include "curve.h"
#include "../rand/rand.h"

using curve::Curve;
using curve::CurvePoint;
using curve::CurveType;
using ntl::BN;
using ntl::Rand;

namespace curve {
namespace enc {

void ECIES::set_curve_type(curve::CurveType curve_type) {
    curve_type_ = curve_type;
}

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

}
}
