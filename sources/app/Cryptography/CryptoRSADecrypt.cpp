/*
 * CryptoRSADecrypt.cpp
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#include <stdint.h>

#include "CryptoRSADecrypt.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
extern "C" {
#include "crypto.h"
}
#endif

uint8_t Crypto_RSA_Decrypt_prvExp[PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE];     // Buffer that will contain the private Exponent
uint8_t Crypto_RSA_Decrypt_prvbMod[PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE];    // Buffer that will contain the private Modulus
uint8_t Crypto_RSA_Decrypt_status;

uint8_t preallocated_buffer[4096];

RSAprivKey_stt Crypto_RSA_Decrypt_PrivKey_st;                           // Structure that will contain the private key for decryption

Crypto_RSA_Decrypt::Crypto_RSA_Decrypt()
{
    Crypto_RSA_Decrypt_status = 0;
}

Crypto_RSA_Decrypt::~Crypto_RSA_Decrypt(){}

/*
 * @brief       Not implementet yet, because there is not generation method in the Cryptolibrary
 * @param
 *
 * @retval      Amount of errors
 */
uint8_t Crypto_RSA_Decrypt::generateKeyPair(uint8_t* pubKey,
                                            uint8_t* pubKey_size,
                                            uint8_t* prvKey,
                                            uint8_t* prvKey_size,
                                            uint8_t* modulus,
                                            uint8_t* modulus_size)
{
    //TODO Include Generation algorithm
    if (!false) {
        //Function not implemented, prevent of errors
        return 1;
    }

    *pubKey_size = (uint8_t)PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE;
    *prvKey_size = (uint8_t)PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE;
    *Crypto_RSA_Decrypt_prvbMod = (uint8_t)PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE;

    Crypto_RSA_Decrypt_status = 1;

    return 0;
}

/*
 * @brief	This Method sets the private Key for decryption
 * @param       prvKey:                 The private Key(exponent) which should be set.
 * @param       prvKey_size:    The size of the private Key.
 * @param       modulus:                The modulus which should be set.
 * @param       modulus_size:   The size of the modulus
 * @retval      Error status:   0 => SUCCESS
 *                                                      1 => Invalid InputSize of Parameter "prvKey_size"	(Expected size is 128 Byte)
 *                                                      2 => Invalid InputSize of Parameter "modulus"		(Expected size is 128 Byte)
 */
uint8_t Crypto_RSA_Decrypt::setPrivateKey(uint8_t* prvKey, uint8_t prvKey_size, uint8_t* modulus, uint8_t modulus_size)
{
    if (PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE != prvKey_size) {
        return 1;
    }

    if (PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE != modulus_size) {
        return 2;
    }

    for (int i = 0; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        Crypto_RSA_Decrypt_prvExp[i] = prvKey[i];
    }

    for (int i = 0; i < PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE; i++) {
        Crypto_RSA_Decrypt_prvbMod[i] = modulus[i];
    }

    //initialize struct
    Crypto_RSA_Decrypt_PrivKey_st.mExponentSize = prvKey_size;
    Crypto_RSA_Decrypt_PrivKey_st.mModulusSize = modulus_size;
    Crypto_RSA_Decrypt_PrivKey_st.pmExponent = Crypto_RSA_Decrypt_prvExp;
    Crypto_RSA_Decrypt_PrivKey_st.pmModulus = Crypto_RSA_Decrypt_prvbMod;

    //TODO Include initialization
    Crypto_RSA_Decrypt_status = 1;

    return 0;
}

/*
 * @brief	This Method decrypts a given Inputmessage
 * @param       encryptedAESInformation:                The encrypted input message which should be decrypted.
 * @param       encryptedAESInformation_size:   The size of the input message.
 * @param       decryptedAESInformation:                The decrypted message will be parsed in this parameter
 * @param       decryptedAESInformation_size:   returns the size of the decrypted message
 * @retval      Error status:                                   0 => SUCCESS
 *                                                                                      1 => There is no decryption key set
 *                                                                                      2 => Invalid size of the input Message		(Expected size is 128 Byte)
 *                                                                                      3 => Error occurred while decrypting (in the Cryptolibrary)
 */
uint8_t Crypto_RSA_Decrypt::getDecryptedAESInformation(uint8_t* encryptedAESInformation,
                                                       int32_t  encryptedAESInformation_size,
                                                       uint8_t* decryptedAESInformation,
                                                       int32_t* decryptedAESInformation_size)
{
    if (1 != Crypto_RSA_Decrypt_status) {
        return 1;
    }

    RSAinOut_stt inOut_st;
    membuf_stt mb;

    mb.mSize = sizeof(preallocated_buffer);
    mb.mUsed = 0;
    mb.pmBuf = preallocated_buffer;

    /* Fill the RSAinOut_stt */
    inOut_st.pmInput = encryptedAESInformation;
    inOut_st.mInputSize = encryptedAESInformation_size;
    inOut_st.pmOutput = decryptedAESInformation;

    if ((0 >= encryptedAESInformation_size) &&
        (0 == (encryptedAESInformation_size % PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE))) {
        return 2;
    }

    if (RSA_SUCCESS !=
        RSA_PKCS1v15_Decrypt(&Crypto_RSA_Decrypt_PrivKey_st, &inOut_st, decryptedAESInformation_size, &mb)) {
        return 3;
    }

    return 0;
}
