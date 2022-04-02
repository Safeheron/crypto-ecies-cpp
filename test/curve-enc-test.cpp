//
// Created by 何剑虹 on 2020/10/22.
//
#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "rand/rand.h"
#include "curve/curve.h"
#include "encode/base64.h"
#include "common/inspect.h"

using namespace ntl;
using curve::Curve;
using curve::CurvePoint;
using curve::CurveType;
using curve::enc::ECIES;
using curve::enc::ECEncJS;
using curve::enc::AuthEnc;
using curve::enc::AuthEncJS;

const std::vector<std::string> message_arr = {
        {0, 1, 2, 3, 4, 5},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33},
};

void testECIES_0(const std::string &message, CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);

    uint8_t *plain = nullptr;
    uint8_t *cypher = nullptr;
    size_t plain_len, cypher_len;

    //BN priv_a = BN::FromDecStr("4050298667054381376040649773970530311598264897556821662677634075002761777");
    //BN priv_b = BN::FromDecStr("2294226772740614508941417891614236736606752960073669253551166842586609531");
    BN priv = Rand::RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECIES enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(pub, (const uint8_t *)message.c_str(), message.length(), &cypher, &cypher_len);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", (const char *)(cypher), cypher_len);
    ok = enc.Decrypt(priv, cypher, cypher_len, &plain, &plain_len);
    EXPECT_TRUE(ok);
    show_mem("plain : ", (const char *)(plain), plain_len);
    for(size_t i = 0; i < plain_len; i ++){
        EXPECT_EQ(message[i], plain[i]);
    }

    free(plain);
    free(cypher);
}

void testECIES_1(const std::string &message, CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);

    std::string plain;
    std::string cypher;

    BN priv = Rand::RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECIES enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(pub, message, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv, cypher, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, ECIES)
{
    for(size_t i = 0; i < message_arr.size(); i++){
        testECIES_0(message_arr[i], CurveType::P256);
        testECIES_1(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testECIES_0(message_arr[i], CurveType::SECP256K1);
        testECIES_1(message_arr[i], CurveType::SECP256K1);
    }
}

void testECEnc_JS(const std::string &message, CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);

    std::string plain;
    std::string cypher;

    BN priv = Rand::RandomBNLt(curv->n);
    CurvePoint pub = curv->g * priv;

    bool ok = true;
    ECEncJS enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(pub, message, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv, cypher, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, ECEnc_JS)
{
    for(size_t i = 0; i < message_arr.size(); i++){
        testECEnc_JS(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testECEnc_JS(message_arr[i], CurveType::SECP256K1);
    }
}

void testAuthEnc(const std::string &message, CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);

    std::string plain;
    std::string cypher;

    BN priv1 = Rand::RandomBNLt(curv->n);
    CurvePoint pub1 = curv->g * priv1;

    BN priv2 = Rand::RandomBNLt(curv->n);
    CurvePoint pub2 = curv->g * priv2;

    bool ok = true;
    AuthEnc enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(priv1, pub2, message, cypher);
    EXPECT_TRUE(ok);
    if(ok) show_mem("cypher: ", cypher.c_str(), cypher.length());

    ok = enc.Decrypt(priv2, pub1, cypher, plain);
    EXPECT_TRUE(ok);
    if(ok) show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        //EXPECT_EQ(message[i], plain[i]);
    }
}

TEST(Curve_ENC, AuthEnc)
{
    for(size_t i = 0; i < message_arr.size(); i++){
        testAuthEnc(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testAuthEnc(message_arr[i], CurveType::SECP256K1);
    }
}

void testAuthEncJS(const std::string &message, CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);

    std::string plain;
    std::string cypher;

    BN priv1 = Rand::RandomBNLt(curv->n);
    CurvePoint pub1 = curv->g * priv1;

    BN priv2 = Rand::RandomBNLt(curv->n);
    CurvePoint pub2 = curv->g * priv2;

    bool ok = true;
    AuthEncJS enc;
    enc.set_curve_type(c_type);
    ok = enc.Encrypt(priv1, pub2, message, cypher);
    EXPECT_TRUE(ok);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv2, pub1, cypher, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < message.length(); i ++){
        EXPECT_EQ(message[i], plain[i]);
    }
}

void testAuthEncJS_Compatibility(CurveType c_type){
    const Curve *curv = curve::GetCurveParam(c_type);
    // The cypher data for javascript oriented encryption library is encoded in base64.
    const std::string cypher_js_base64 = "CBRdOrctYM-sn3tzoPy6A1UpenJTw1tA3rqkzXrpdUYPtQRoltFL4RLK-GG6AEZN5L3kD_mkMQGwSkXU3iDt3l48xvFGuu2FHiERVXBKqdsVvC5vFZetvfCwQYWe3NL0crBp6P-VgKdHUuxsw1U9kx2OAIBgm7BLBq1d9x0wXGIuqmkkU1vbrA8gnYx26S2hhd4mYX_mOVaD27BkIS6IhQ..";
    const std::string plain_js = "hello";

    bool ok = true;
    std::string plain;
    std::string cypher;
    ok = encode::Base64::DecodeFromUrlBase64(cypher, cypher_js_base64);
    EXPECT_TRUE(ok);

    BN priv1 = BN::FromHexStr("cba6b44f9ee7cefc5512928c92f0a178ffc25c50ed5f4d7d35f7402be1008e5e");
    CurvePoint pub1 = curv->g * priv1;

    BN priv2 = BN::FromHexStr("be2ea963ba0b0c626abb6be58c204a5df66c9924c8267f101be9cb5cca96d6a4");
    CurvePoint pub2 = curv->g * priv2;

    AuthEncJS enc;
    enc.set_curve_type(c_type);
    show_mem("cypher: ", cypher.c_str(), cypher.length());
    ok = enc.Decrypt(priv2, pub1, cypher, plain);
    EXPECT_TRUE(ok);
    show_mem("plain : ", plain.c_str(), plain.length());
    for(size_t i = 0; i < plain_js.length(); i ++){
        EXPECT_EQ(plain_js[i], plain[i]);
    }
}


TEST(Curve_ENC, AuthEnc_JS)
{
    for(size_t i = 0; i < message_arr.size(); i++) {
        testAuthEncJS(message_arr[i], CurveType::P256);
    }
    for(size_t i = 0; i < message_arr.size(); i++){
        testAuthEncJS(message_arr[i], CurveType::SECP256K1);
    }
    testAuthEncJS_Compatibility(CurveType::P256);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
