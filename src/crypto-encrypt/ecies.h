//
// Created by 何剑虹 on 2021/10/8.
//

#ifndef CRYPTO_BASIC_EC_IES_H
#define CRYPTO_BASIC_EC_IES_H

#include "./curve_point.h"

namespace curve {
namespace enc {

class ECIES{
private:
    curve::CurveType curve_type_;
public:
    ECIES(){ curve_type_ = curve::CurveType::P256; }
    void set_curve_type(curve::CurveType curve_type);
    // You should free space like this:
    // free(*cypher);
    bool Encrypt(const CurvePoint &pub, const unsigned char *in_plain, size_t int_plain_len, unsigned char **out_cypher, size_t *out_cypher_len);
    // You should free space like this:
    // free(*plain);
    bool Decrypt(const ntl::BN &priv, const unsigned char *in_cypher, size_t in_cypher_len, unsigned char **out_plain, size_t *out_plain_len);

    bool Encrypt(const CurvePoint &pub, const std::string &in_plain, std::string &out_cypher);
    bool Decrypt(const ntl::BN &priv, const std::string &in_cypher, std::string &out_plain);
};

}
}


#endif //CRYPTO_BASIC_EC_IES_H
