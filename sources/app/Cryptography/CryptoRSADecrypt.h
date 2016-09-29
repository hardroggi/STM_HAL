/*
 * CryptoRSADecrypt.h
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTORSADECRYPT_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTORSADECRYPT_H_

#define PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE 128
#define PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE 128
#define PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE 128

class Crypto_RSA_Decrypt
{
public:
    Crypto_RSA_Decrypt();
    virtual ~Crypto_RSA_Decrypt();
    uint8_t generateKeyPair(uint8_t* pubKey,
                            uint8_t* pubKey_size,
                            uint8_t* prvKey,
                            uint8_t* prvKey_size,
                            uint8_t* modulus,
                            uint8_t* modulus_size);
    uint8_t setPrivateKey(uint8_t* prvKey, uint8_t prvKey_size, uint8_t* modulus, uint8_t modulus_size);
    uint8_t getDecryptedAESInformation(uint8_t* encryptedAESInformation,
                                       int32_t  encryptedAESInformation_size,
                                       uint8_t* decryptedAESInformation,
                                       int32_t* decryptedAESInformation_size);
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTORSADECRYPT_H_ */
