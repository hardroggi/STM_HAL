/*
 * CryptoRSASign.cpp
 *
 *  Created on: 30.08.2016
 *      Author: tobias
 */
#include <stdint.h>

#include "CryptoRSASignVerify.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif
#ifndef PMD_CRYPTO_RSA_SIGN
#define PMD_CRYPTO_RSA_SIGN
#include "rsa.h"
#endif

bool Crypto_RSA_Sign_Verify_signatureSet;
bool Crypto_RSA_Sign_Verify_pubkSet;
uint8_t Crypto_RSA_Sign_Verify_preallocatedBuffer[4096];                        // buffer required for internal allocation of memory
uint8_t Crypto_RSA_Sign_Verify_pubExp[PMD_CRYPTO_RSA_SIGN_EXP_SIZE];            // Buffer that will contain the public Exponent
uint8_t Crypto_RSA_Sign_Verify_pubMod[PMD_CRYPTO_RSA_SIGN_MOD_SIZE];            // Buffer that will contain the public Modulus
uint8_t Crypto_RSA_Sign_Verify_signature[PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE];    // Buffer that will contain the signature

RSApubKey_stt Crypto_RSA_Sign_Verify_pubKeySt;                              // Structure that will contain the public key for verifying the signature

Crypto_RSA_Sign_Verify::Crypto_RSA_Sign_Verify()
{
    Crypto_RSA_Sign_Verify_pubkSet = false;
    Crypto_RSA_Sign_Verify_signatureSet = false;
}

Crypto_RSA_Sign_Verify::~Crypto_RSA_Sign_Verify()
{
    // TODO Auto-generated destructor stub
}

/**
 * @brief       This functions stores the public exponent and the public Modulus in the class
 * @param       pubKey:			The public key, which should be stored in the class
 * @param       pubKey_size:	The size of the public key
 * @param       modulus:		The public modulus, which should be stored in the class
 * @param       modulus_size:	The size of the modulus
 * @retval      error_code:     0 => SUCCESS
 *                                                      1 => Invalid key size (expected value = 128)
 *                                                      2 => Invalid modulus size (expected value = 128)
 */
uint8_t Crypto_RSA_Sign_Verify::SetPublicKey(uint8_t* pubKey,
                                             uint8_t  pubKey_size,
                                             uint8_t* modulus,
                                             uint8_t  modulus_size)
{
    if (PMD_CRYPTO_RSA_SIGN_EXP_SIZE != pubKey_size) {
        return 1;
    }

    if (PMD_CRYPTO_RSA_SIGN_MOD_SIZE != modulus_size) {
        return 2;
    }
    Crypto_RSA_Sign_Verify_pubKeySt.mExponentSize = pubKey_size;
    Crypto_RSA_Sign_Verify_pubKeySt.mModulusSize = modulus_size;

    for (int i = 0; i < pubKey_size; i++) {
        Crypto_RSA_Sign_Verify_pubExp[i] = pubKey[i];
    }
    Crypto_RSA_Sign_Verify_pubKeySt.pmExponent = Crypto_RSA_Sign_Verify_pubExp;

    for (int i = 0; i < modulus_size; i++) {
        Crypto_RSA_Sign_Verify_pubMod[i] = modulus[i];
    }
    Crypto_RSA_Sign_Verify_pubKeySt.pmModulus = Crypto_RSA_Sign_Verify_pubMod;

    Crypto_RSA_Sign_Verify_pubkSet = true;
    return 0;
}

/**
 * @brief       This functions stores the signed Hash in the class
 * @param       signedHash:			The public exponent, which should be stored in the class
 * @param       signedHash_size:	The size of the exponent
 * @retval      error_code:             0 => SUCCESS
 *                                                              1 => Invalid size of the signed hash (expected value = 128)
 */
uint8_t Crypto_RSA_Sign_Verify::SetSignedHash(uint8_t* signedHash, uint8_t signedHash_size)
{
    if (PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE != signedHash_size) {
        return 1;
    }
    for (int i = 0; i < signedHash_size; i++) {
        Crypto_RSA_Sign_Verify_pubMod[i] = signedHash[i];
    }

    Crypto_RSA_Sign_Verify_signatureSet = true;

    return 0;
}

/**
 * @brief       This functions stores the signed Hash in the class
 * @param       signedHash:			The public exponent, which should be stored in the class
 * @param       signedHash_size:	The size of the exponent
 * @retval      error_code:             0 => SUCCESS SIGNATUR IS VALID
 *                                                              1 => "SUCCESS" SIGNATUR IS INVALID
 *                                                              2 => No Public Key set
 *                                                              3 => No Signature set
 *                                                              4 => Invalid Hash-size
 *                                                              5 => Error while verifying process
 */
uint8_t Crypto_RSA_Sign_Verify::VerifyHash(uint8_t* signedHash, uint8_t signedHash_size)
{
    if (!Crypto_RSA_Sign_Verify_pubkSet) {
        return 2;
    }

    if (!Crypto_RSA_Sign_Verify_signatureSet) {
        return 3;
    }

    if (PMD_CRYPTO_RSA_SIGN_HASH_SIZE != signedHash_size) {
        return 4;
    }

    /* Initialize the membuf_stt that must be passed to the RSA functions */
    membuf_stt mbSt;
    mbSt.mSize = sizeof(Crypto_RSA_Sign_Verify_preallocatedBuffer);
    mbSt.mUsed = 0;
    mbSt.pmBuf = Crypto_RSA_Sign_Verify_preallocatedBuffer;

    int32_t status = RSA_PKCS1v15_Verify(&Crypto_RSA_Sign_Verify_pubKeySt,
                                         signedHash,
                                         E_SHA256,
                                         Crypto_RSA_Sign_Verify_signature,
                                         &mbSt);
    if (SIGNATURE_VALID == status) {
        return 0;
    } else {
        if (SIGNATURE_INVALID == status) {
            return 1;
        } else {
            return 5;
        }
    }
}
