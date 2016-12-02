/**
 * 3DES, jianlinlong@gmail.com
 * MIT lincense
 */

#ifndef _D_DES_H_
#define _D_DES_H_

#include <string>
#include <memory>
#include "assert.h"
#include "mbedtls_des.h"


template<typename T>
class DES
{
public:
    DES(const char *key, int key_len = 0, const char *iv = NULL, int iv_len = 0) 
    {
        assert(NULL != key);
        if (0 == key_len) {
            key_len = strlen(key);
        }
        key_ = std::string(key, key_len);

        if (NULL != iv) {
            if (0 == iv_len) {
                iv_len = strlen(iv);
            }
            if (iv_len > 0) {
                iv_ = std::string(iv, iv_len);
            }
        }

        data_.read_data_key(key_);
    }

    DES(const std::string& key, const std::string& iv = "")
        :DES(key.c_str(), key.length(), iv.c_str(), iv.length())
    {}

    DES(const DES &r) = delete;
    DES operator=(const DES &r) = delete;

public:
    inline std::string encrypt(const std::string& data) {
        return encrypt(data.data(), data.length());
    }

    inline std::string decrypt(const std::string& data, bool padding = true) {
        return decrypt(data.data(), data.length(), padding);
    }

    /*
    * @brief DES/3DES加密
    * @param data 待加密的数据
    * @param len  数据长度
    * @return 返回加密后的数据, string.data()是数据, string.size()是长度
    */
    inline std::string encrypt(const char *data, int len) {
        std::string ret;
        if (len < 0) {
            return ret;
        }

        //about padding, please see：http://blog.csdn.net/alonesword/article/details/17385359
        //now I choose PKCS5
        int padding = 8 - len % 8;
        int new_len = len + padding;
        std::unique_ptr<unsigned char[]> padding_data(new unsigned char[new_len]);
        unsigned char* after_padding = padding_data.get();
        memcpy(after_padding, data, len);
        for (int i = 0; i < padding; i++) {
            after_padding[len + i] = padding;
        }

        ret.resize(new_len);

        //
        data_.setkey_enc(&data_.ctx_, (const unsigned char*)data_.data_key_);
        if (!iv_.empty()) {
            unsigned char iv[8] = { 0 };
            memcpy(iv, (unsigned char*)iv_.data(), std::min(8u, iv_.size()));
            data_.crypt_cbc(&data_.ctx_, MBEDTLS_DES_ENCRYPT, new_len, iv, after_padding, (unsigned char*)ret.data());
        } else {
            unsigned char* output = (unsigned char*)ret.data();
            unsigned char* input  = after_padding;
            while (new_len > 0) {
                data_.crypt_ecb(&data_.ctx_, input, output);
                input += 8;
                output += 8;
                new_len -= 8;
            }
        }

        return ret;
    }

    /*
    * @brief DES/3DES解密
    * @param data 待解密的数据, 必然是8的倍数
    * @param len  数据长度
    * @param padding 是否用padding来解包, 默认都是padding的
    * @return 返回加密后的数据, string.data()是数据, string.size()是长度
    */
    inline std::string decrypt(const char *data, int len, bool padding = true) {
        std::string ret;
        if (len <= 0 || len % 8 != 0) {
            return ret;
        }
        ret.resize(len);

        //
        int new_len = len;
        data_.setkey_dec(&data_.ctx_, (const unsigned char*)data_.data_key_);
        if (!iv_.empty()) {
            unsigned char iv[8] = { 0 };
            memcpy(iv, (unsigned char*)iv_.data(), std::min(8u, iv_.size()));
            data_.crypt_cbc(&data_.ctx_, MBEDTLS_DES_DECRYPT, new_len, iv, (const unsigned char*)data, (unsigned char*)ret.data());
        } else {
            unsigned char* output = (unsigned char*)ret.data();
            const unsigned char* input = (const unsigned char*)data;
            while (new_len > 0) {
                data_.crypt_ecb(&data_.ctx_, input, output);
                input += 8;
                output += 8;
                new_len -= 8;
            }
        }

        if (padding) {
            int pos = ret.size() - (int)ret.back();
            if (pos > 0) {
                ret.erase(pos, std::string::npos);
            } else {
                ret.clear();
            }
        }

        return ret;
    }


protected:
    std::string key_;
    std::string iv_;
    T data_;
};


///////////////////////////////////////////////////////////////////////////////
///////internal///////
struct DES_Trait {
    static constexpr auto setkey_enc = mbedtls_des_setkey_enc;
    static constexpr auto setkey_dec = mbedtls_des_setkey_dec;
    static constexpr auto crypt_cbc  = mbedtls_des_crypt_cbc;
    static constexpr auto crypt_ecb  = mbedtls_des_crypt_ecb;

    DES_Trait() {
        mbedtls_des_init(&ctx_);
    }

    ~DES_Trait() {
        mbedtls_des_free(&ctx_);
    }

    void read_data_key(const std::string& key) {
        memset(data_key_, 0x0, sizeof(data_key_));
        memcpy(data_key_, key.data(), std::min(8u, key.size()));
    }

    mbedtls_des_context ctx_;
    char data_key_[8];
};

struct DES3_Trait {
    static constexpr auto setkey_enc = mbedtls_des3_set3key_enc;
    static constexpr auto setkey_dec = mbedtls_des3_set3key_dec;
    static constexpr auto crypt_cbc  = mbedtls_des3_crypt_cbc;
    static constexpr auto crypt_ecb  = mbedtls_des3_crypt_ecb;

    DES3_Trait() {
        mbedtls_des3_init(&ctx_);
    }

    ~DES3_Trait() {
        mbedtls_des3_free(&ctx_);
    }

    void read_data_key(const std::string& key) {
        memset(data_key_, 0x0, sizeof(data_key_));

        int key_len = key.length();
        if (key_len > 16) {
            memcpy(data_key_, key.data(), std::min(24, key_len));
        }
        else if (key_len > 8) {
            memcpy(data_key_, key.data(), std::min(16, key_len));
            //memcpy(data_key_ + 16, data_key_, 8);  //这里注释掉，因为要与 http://tool.chacuo.net/crypt3des 保持一致
        }
        else {
            int n = std::min(8, key_len);
            memcpy(data_key_,      key.data(), n);
            memcpy(data_key_ + 8,  key.data(), n);
            memcpy(data_key_ + 16, key.data(), n);
        }
    }

    mbedtls_des3_context ctx_;
    char data_key_[24];
};
///////////////////////////////////////////////////////////////////////////////

//use this class
typedef DES<DES_Trait>  DES_Cipher;
typedef DES<DES3_Trait> DES3_Cipher;

#endif
