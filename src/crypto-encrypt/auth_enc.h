//
// Created by 何剑虹 on 2021/10/8.
//

#ifndef CRYPTO_BASIC_AUTH_ENC_H
#define CRYPTO_BASIC_AUTH_ENC_H

#include "./curve_point.h"

namespace curve {
namespace enc {

class AuthEnc{
private:
    curve::CurveType curve_type_;
public:
    AuthEnc(){ curve_type_ = curve::CurveType::P256; }
    void set_curve_type(curve::CurveType curve_type);
    bool Encrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const std::string &in_plain, std::string &out_cypher);
    bool Encrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const unsigned char *in_plain, size_t in_plain_len, unsigned char **out_cypher, size_t *out_cypher_len);
    bool Decrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const std::string &in_cypher, std::string &out_plain);
    bool Decrypt(const ntl::BN &local_priv, const CurvePoint &remote_pub, const unsigned char *in_cypher, size_t in_cypher_len, unsigned char **out_plain, size_t *out_plain_len);
};

}
}


#endif //CRYPTO_BASIC_AUTH_ENC_H
