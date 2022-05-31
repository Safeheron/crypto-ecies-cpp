/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_CRYPTO_ECIES_H
#define SAFEHERON_CRYPTO_ECIES_H

#include <crypto-bn/bn.h>
#include <crypto-curve/curve_point.h>
#include <string>

#define MAX_INPUT_DATA_LEN  4*1024*1024 // 4 MBytes
#define MAX_CBC_IV_LEN      64  //in Bytes
#define MAX_SALT_IV_LEN     512 //in Bytes
#define MAX_HMAC_KEY_LEN    64  //in Bytes
#define MAX_HMAC_LEN        64  //in Bytes

using namespace safeheron::bignum;
using namespace safeheron::curve;

class IKDF;
class ISYMM;
class IHMAC;

namespace curve {
namespace enc {
#if 0
/*
 *  ECIES algorithms
 */
enum class ECIESAlg: unsigned int {
    INVALID_ALG = 0,
    ECIESwithDESedeCBC = 1,             //SHA1with3DES-CBC, in default: DES key size is 192, mac key size is 128
    ECIESwithSHA256andDESedeCBC = 2,    //SHA256with3DES-CBC, in default: DES key size is 192, mac key size is 128
    ECIESwithSHA384andDESedeCBC = 3,    //SHA384with3DES-CBC, in default: DES key size is 192, mac key size is 128
    ECIESwithSHA512andDESedeCBC = 4,    //SHA512with3DES-CBC, in default: DES key size is 192, mac key size is 128
    ECIESwithAESCBC = 5,                //SHA1withAES-CBC, in default: AES key size is 256, mac key size is 128
    ECIESwithSHA256andAESCBC = 6,       //SHA256withAES-CBC, in default: AES key size is 256, mac key size is 128
    ECIESwithSHA384andAESCBC = 7,       //SHA384withAES-CBC, in default: AES key size is 256, mac key size is 128
    ECIESwithSHA512andAESCBC = 8        //SHA512withAES-CBC, in default: AES key size is 256, mac key size is 128
};

/*
 *  Hash algorithms for KDF and MAC in ecies
 */
enum class HASHAlg: unsigned int {
    INVALID_ALG = 0,
    SHA1 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4
};
#endif //0

/*
 *  Symmetic algorithms definition
 */
enum class SYMM_ALG: unsigned int {
    INVALID_ALG = 0,
    DESede_CBC = 1,
    AES128_CBC = 2,
    AES192_CBC = 3,
    AES256_CBC = 4
};

/*
 *  Key derivation function types
 */
enum class KDF_TYPE: unsigned int {
    INVALID_TYPE = 0,
    KDF_X9_63_With_SHA1 = 1,
    KDF_X9_63_With_SHA256 = 2,
    KDF_X9_63_With_SHA384 = 3,
    KDF_X9_63_With_SHA512 = 4,
    KDF1_18033_With_SHA1 = 5,
    KDF1_18033_With_SHA256 = 6,
    KDF1_18033_With_SHA384 = 7,
    KDF1_18033_With_SHA512 = 8,
    KDF2_18033_With_SHA1 = 9,
    KDF2_18033_With_SHA256 = 10,
    KDF2_18033_With_SHA384 = 11,
    KDF2_18033_With_SHA512 = 12
};

/*
 *  HMAC algorithm types
 */
enum class HMAC_ALG: unsigned int {
    INVALID_ALG = 0,
    HMAC_SHA1 = 1,
    HMAC_SHA256 = 2,
    HMAC_SHA384 = 3,
    HMAC_SHA512 = 4
};

class ECIES{
private:
    CurveType curve_type_;
    //
    IKDF*       kdf_;
    ISYMM*      symm_;
    IHMAC*      hmac_;
    SYMM_ALG    symm_alg_;
    //HASHAlg hash_alg_;
    //ECIESAlg ecies_alg_;
    //int symm_key_size_;
    //int mac_key_size_;
private:
    void free();
public:
    ECIES();
    virtual ~ECIES();
    void set_curve_type(CurveType curve_type);
#if 0
    // You should free space like this:
    // free(*cypher);
    bool Encrypt(const CurvePoint &pub, const unsigned char *in_plain, size_t int_plain_len, unsigned char **out_cypher, size_t *out_cypher_len);
    // You should free space like this:
    // free(*plain);
    bool Decrypt(const ntl::BN &priv, const unsigned char *in_cypher, size_t in_cypher_len, unsigned char **out_plain, size_t *out_plain_len);

    bool Encrypt(const CurvePoint &pub, const std::string &in_plain, std::string &out_cypher);
    bool Decrypt(const ntl::BN &priv, const std::string &in_cypher, std::string &out_plain);
#endif //0
/*
    // Set ecies algorithm
    // If this API is not called, we use ECIESwithSHA512andAESCBC in default.
    //
    // alg: one of ECIESAlg value.
    bool set_ecies_alg(const ECIESAlg alg);
    // Return current ecies algorithm in using
    ECIESAlg get_ecies_alg();

    // Set symmetic key size and MAC key size in ecies
    // If this API is not called, we use 192 for DESede and 256 for AES.
    //
    // symm_key_size: the AES key size, should be 128,192 or 256.
    //                it will be ingored if current ecies algorithm uses DESede for symmetic encryption
    // mac_key_size: the MAC key size, it is 128 in default.
    bool set_key_size(const int symm_key_size, const int mac_key_size);
    // Return the symmetic key size and mac key size, in bits
    void get_key_size(int & symm_key_size, int & mac_key_size);
*/
    // Set symmetic algorithm using in ECIE
    // If this API is not called, we use AES256_CBC in default.
    //
    // alg: one of SYMM_ALG value.
    bool set_symm_alg(SYMM_ALG alg);
    // Return current symmetic algorithm in using currently
    SYMM_ALG get_symm_alg();

    // Set key derivation function type
    // If this API is not called, we use KDF_X9_63_SHA512 in default.
    //
    // kdf: KDF type, should be one of KDF_TYPE.
    bool set_kdf_type(KDF_TYPE kdf);
    // Return the KDF type is using currently
    KDF_TYPE get_kdf_type();

    // Set HMAC algorithm type
    // If this API is not called, we use HMAC_SHA512 in default.
    //
    // hash: Hash algorithm used in HMAC, should be one of HMAC_ALG.
    bool set_mac_type(HMAC_ALG mac); 
    // Return the HMAC type is using currently
    HMAC_ALG get_mac_type();

    // Set derivation IV (salt) for KDF_X9_63 only, null in default.
    // This API takes no effect on KDF1 and KDF2.
    //
    // iv: IV bytes
    // len: IV length, in bytes
    bool set_derivation_iv(const unsigned char* iv, const size_t len);
    // Return the derivation IV data which is using in current KDF.
    void get_derivation_iv(std::string & out_iv);

    // Set encoding IV for HMAC
    // If this API is not called, we use null in default.
    //
    // iv: IV bytes
    // len: IV length, in bytes
    bool set_mac_iv(const unsigned char* iv, const size_t len);
    // Return the encoding IV data which is using in current HMAC.
    void get_mac_iv(std::string & out_iv);

    // Encrypt and decrypt
    // out_cypher is in format: 0x04|x|y|c|h
    bool EncryptWithIV(const CurvePoint &pubkey, const std::string &in_plain, const std::string &in_iv, std::string &out_cypher);
    bool Encrypt(const CurvePoint &pubkey, const std::string &in_plain, std::string &out_iv, std::string &out_cypher);
    bool Decrypt(const BN &privkey, const std::string &in_cypher, const std::string &in_iv, std::string &out_plain);
    //
    bool EncryptWithIV(const CurvePoint &pubkey, const unsigned char *in_plain, size_t in_plain_len, const unsigned char *in_iv, size_t in_iv_len, std::string &out_cypher);
    bool Encrypt(const CurvePoint &pubkey, const unsigned char *in_plain, size_t in_plain_len, std::string &out_iv, std::string &out_cypher);
    bool Decrypt(const BN &privkey, const unsigned char *in_cypher, size_t in_cypher_len, const unsigned char *in_iv, size_t in_iv_len, std::string &out_plain);

    // Encrypt pack and decrypt pack
    // out_cypher is in format: 0x04|x|y|c|h|iv, iv is 8 bytes for DESede, and 16 bytes for AES
    bool EncryptPackWithIV(const CurvePoint &pubkey, const std::string &in_plain, const std::string &in_iv, std::string &out_cypher);
    bool EncryptPack(const CurvePoint &pubkey, const std::string &in_plain, std::string &out_cypher);
    bool DecryptPack(const BN &privkey, const std::string &in_cypher, std::string &out_plain);
    //
    bool EncryptPackWithIV(const CurvePoint &pubkey, const unsigned char *in_plain, size_t in_plain_len, const unsigned char *in_iv, size_t in_iv_len, std::string &out_cypher);
    bool EncryptPack(const CurvePoint &pubkey, const unsigned char *in_plain, size_t in_plain_len, std::string &out_cypher);
    bool DecryptPack(const BN &privkey, const unsigned char *in_cypher, size_t in_cypher_len, std::string &out_plain);
};

}
}


#endif //SAFEHERON_CRYPTO_ECIES_H
