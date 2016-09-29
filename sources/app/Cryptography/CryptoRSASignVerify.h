/*
 * CryptoRSASign.h
 *
 *  Created on: 30.08.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_

#define PMD_CRYPTO_RSA_SIGN_EXP_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_MOD_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_HASH_SIZE 32

class Crypto_RSA_Sign_Verify
{
public:
    Crypto_RSA_Sign_Verify();
    virtual ~Crypto_RSA_Sign_Verify();
    uint8_t SetPublicKey(uint8_t* pubKey, uint8_t pubKey_size, uint8_t* modulus, uint8_t modulus_size);
    uint8_t SetSignedHash(uint8_t* signedHash, uint8_t signedHash_size);
    uint8_t VerifyHash(uint8_t* unsignedHash, uint8_t unsignedHash_size);
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_ */
