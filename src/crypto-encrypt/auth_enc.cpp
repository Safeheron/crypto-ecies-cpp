//
// Created by 何剑虹 on 2021/10/8.
//

#include "auth_enc.h"
#include "curve_ecdsa.h"
#include "ecies.h"
#include "../rand/rand.h"

using ntl::BN;
using ntl::Rand;

namespace curve {
namespace enc {

void AuthEnc::set_curve_type(curve::CurveType curve_type) {
    curve_type_ = curve_type;
}

bool AuthEnc::Encrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const unsigned char *in_plain, size_t in_plain_len,
                         unsigned char **out_cypher, size_t *out_cypher_len) {
    bool ok = true;
    SHA256_CTX ctx;
    uint8_t digest[32];
    unsigned char sig[64];
    unsigned char *raw_cypher;
    size_t raw_cypher_len;
    CurveType c_type = remote_pub.GetCurveType();
    const Curve * curv = GetCurveParam(c_type);
    if(curv == nullptr) return false;

    // Encrypt
    ECIES ecies;
    ecies.set_curve_type(c_type);
    ok = ecies.Encrypt(remote_pub, in_plain, in_plain_len, &raw_cypher, &raw_cypher_len);
    if (!ok) return false;

    // Get digest of cypher data
    sha256_Init(&ctx);
    sha256_Update(&ctx, raw_cypher, raw_cypher_len);
    sha256_Final(&ctx, digest);

    // Sign
    curve::ecdsa::Sign(c_type, local_priv, digest, sig, NULL, NULL);

    // Construct the output
    *out_cypher_len = raw_cypher_len + 64;
    *out_cypher = (unsigned char *) malloc(*out_cypher_len);
    memcpy(*out_cypher, raw_cypher, raw_cypher_len);
    memcpy(*out_cypher + raw_cypher_len, sig, 64);

    free(raw_cypher);
    return true;
}

bool AuthEnc::Decrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const unsigned char *in_cypher, size_t in_cypher_len,
                         unsigned char **out_plain, size_t *out_plain_len) {
    bool ok = true;
    unsigned char sig[64];
    unsigned char *t_plain = nullptr;
    size_t t_plain_len = 0;
    CurveType c_type = remote_pub.GetCurveType();

    // Get digest of raw cypher data (length: cypher_len - 64)
    uint8_t digest[32];
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, in_cypher, in_cypher_len - 64);
    sha256_Final(&ctx, digest);

    // Verify signature
    memcpy(sig, in_cypher + in_cypher_len - 64, 64);
    ok = curve::ecdsa::Verify(c_type, remote_pub, sig, digest);
    if (!ok) return false;

    // Decrypt
    ECIES ecies;
    ecies.set_curve_type(c_type);
    ok = ecies.Decrypt(local_priv, in_cypher, in_cypher_len - 64, &t_plain, &t_plain_len);
    if (!ok) return false;

    *out_plain_len = t_plain_len;
    *out_plain = t_plain;

    return true;
}

bool AuthEnc::Encrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const std::string &in_plain, std::string &out_cypher){
    uint8_t * t_cypher = nullptr;
    size_t t_cypher_len = 0;
    bool ok = Encrypt(local_priv, remote_pub, (unsigned char *)in_plain.c_str(), in_plain.length(), &t_cypher, &t_cypher_len);
    if(!ok) return false;
    out_cypher.assign((const char*)t_cypher, t_cypher_len);
    free(t_cypher);
    return true;
}

bool AuthEnc::Decrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const std::string &in_cypher, std::string &out_plain){
    unsigned char *t_plain = nullptr;
    size_t t_plain_len = 0;
    bool ok = Decrypt(local_priv, remote_pub, (const unsigned char *)in_cypher.c_str(), in_cypher.length(), &t_plain, &t_plain_len);
    if(!ok) return false;
    out_plain.assign((char *)t_plain, t_plain_len);
    free(t_plain);
    return true;
}


}
}