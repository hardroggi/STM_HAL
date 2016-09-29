/*
 * Cryptography_ut.cpp
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */
#include "unittest.h"

#include <stdint.h>
#include <cmath>
#include <stdio.h>

#include "Cryptography.h"
#include "CryptoRSADecrypt.h"
#include "CryptoRSASignVerify.h"
#include "CryptoSHA256.h"
#include "CryptoAES.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif

#define AES_ENCRYPTED_TESTMASSAGE_LENGTH 64
#define AES_DECRYPTED_TESTMASSAGE_LENGTH 64

uint8_t rsaPubKey[PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE];
uint8_t rsaPrvKey[PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE];
uint8_t rsaMod[PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE];
uint8_t rsaPubKey_size;
uint8_t rsaPrvKey_size;
uint8_t rsaMod_size;
uint8_t aesDecryptedOutputbuffer[AES_ENCRYPTED_TESTMASSAGE_LENGTH];
uint16_t aesDecryptedOutput_size;

/**********Test data**********/
//#warning no real RSA Key-Pairs, AES Information oder Signatures. Only random Numbers.
const uint8_t rsaDecryptModulus[] = {
    0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
    0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77,
    0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
    0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37,
    0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
    0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
    0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64, 0xc4,
    0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
};
const uint8_t rsaDecryptPubKey[] = {
    0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44, 0x29, 0xfc, 0x4d, 0x9a,
    0x33, 0xa5, 0x04, 0x2a, 0x90, 0xb2, 0x7d, 0x4f, 0x54, 0x51, 0xca, 0x9b, 0xbb, 0xd0, 0xb4, 0x47,
    0x94, 0xa7, 0x24, 0xac, 0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
    0xa3, 0x95, 0x74, 0x50, 0x1a, 0x53, 0x26, 0x83, 0x10, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c,
    0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70, 0x7c, 0x3e, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27,
    0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3, 0x4f, 0x9e, 0x50, 0x3b,
    0xd8, 0x0c, 0x06, 0x22, 0xad, 0x79, 0xc6, 0xdc, 0xee, 0x88, 0x35, 0x47, 0xc6, 0xa3, 0xb3, 0x25,
    0x71, 0xa1, 0x01, 0xaf, 0x88, 0x43, 0x40, 0xae, 0xf9, 0x88, 0x5f, 0x2a, 0x4b, 0xbe, 0x92, 0xe8,
};
const uint8_t rsaDecryptPrvKey[] = {
    0xa3, 0xb3, 0x25, 0x06, 0x22, 0xad, 0x79, 0xc6, 0x47, 0xc6, 0x50, 0x1a, 0x53, 0xbe, 0x51, 0xca,
    0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44, 0x29, 0xfc, 0x4d, 0x9a,
    0x33, 0xa5, 0x88, 0x43, 0x40, 0xae, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27, 0xb2, 0x7d, 0x4f, 0x54,
    0x94, 0xa7, 0x24, 0xac, 0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
    0x90, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c, 0x9b, 0xbb, 0xd0, 0xb4, 0x47, 0xa3, 0x95, 0x74,
    0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70, 0x7c, 0x3e, 0xd8, 0x0c, 0xdc, 0xee, 0x88, 0x35,
    0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3, 0x4f, 0x9e, 0x50, 0x3b,
    0x71, 0x26, 0x83, 0x10, 0x4b, 0xa1, 0x01, 0xaf, 0xf9, 0x88, 0x5f, 0x2a, 0x04, 0x2a, 0x92, 0xe8,
};
uint8_t rsaEncryptedAESInformation[] = {
    0x6b, 0xc3, 0xa0, 0x66, 0x56, 0x84, 0x29, 0x30, 0xa2, 0x47, 0xe3, 0x0d, 0x58, 0x64, 0xb4, 0xd8,
    0x19, 0x23, 0x6b, 0xa7, 0xc6, 0x89, 0x65, 0x86, 0x2a, 0xd7, 0xdb, 0xc4, 0xe2, 0x4a, 0xf2, 0x8e,
    0x7f, 0x3d, 0x24, 0x08, 0x7d, 0xdb, 0x6f, 0x2b, 0x72, 0x09, 0x61, 0x67, 0xfc, 0x09, 0x7c, 0xab,
    0xca, 0xef, 0x89, 0x3f, 0x0d, 0x6f, 0xcc, 0x2d, 0x0c, 0x91, 0xec, 0x01, 0x36, 0x93, 0xb4, 0xea,
    0x00, 0xb8, 0x0c, 0xd4, 0x9a, 0xac, 0x4e, 0xcb, 0x5f, 0x89, 0x11, 0xaf, 0xe5, 0x39, 0xad, 0xa4,
    0xa8, 0xf3, 0x82, 0x3d, 0x1d, 0x13, 0xe4, 0x72, 0xd1, 0x49, 0x05, 0x47, 0xc6, 0x59, 0xc7, 0x61,
    0x18, 0xe9, 0xa4, 0x58, 0xfc, 0xb6, 0x34, 0xcd, 0xce, 0x8e, 0xe3, 0x58, 0x94, 0xc4, 0x84, 0xd7,
    0x86, 0xbb, 0x53, 0x1f, 0x03, 0x35, 0x8b, 0xe5, 0xfb, 0x74, 0x77, 0x7c, 0x60, 0x86, 0xf8, 0x50,
};
const uint8_t rsaDecryptedAESInformation[] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
uint8_t aesEncryptedTestMessage[] = {
    0xa3, 0x39, 0xe1, 0x37, 0xb7, 0xb6, 0x1f, 0xc5,
    0x32, 0xd9, 0x41, 0x59, 0x6a, 0xd8, 0x5b, 0x55,
    0xaa, 0x85, 0x16, 0x3a, 0x70, 0x5c, 0xa2, 0xea,
    0x95, 0x3f, 0xb2, 0x1d, 0x19, 0x9a, 0x6b, 0x25,
    0xb9, 0xa9, 0xb5, 0xd0, 0xd4, 0x37, 0x71, 0xf0,
    0x74, 0x5f, 0x2a, 0x00, 0x0f, 0xa9, 0x97, 0x5f,
    0x61, 0x4b, 0xa4, 0x6c, 0x1d, 0xe0, 0xa3, 0x24,
    0x4b, 0x69, 0xf3, 0x86, 0x13, 0x66, 0xf3, 0x3f
};
const uint8_t aesDecryptedTestMessage[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
const uint8_t rsaVerifySignModulus[] = {
    0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
    0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4, 0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
    0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
    0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
    0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b, 0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77,
    0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
    0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64, 0xc4,
    0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8, 0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37,
};
const uint8_t rsaVerifySignPubKey[] = {
    0x33, 0xa5, 0x04, 0x2a, 0x90, 0xb2, 0x7d, 0x4f, 0x54, 0x51, 0xca, 0x9b, 0xbb, 0xd0, 0xb4, 0x47,
    0x71, 0xa1, 0x01, 0xaf, 0x88, 0x43, 0x40, 0xae, 0xf9, 0x88, 0x5f, 0x2a, 0x4b, 0xbe, 0x92, 0xe8,
    0x94, 0xa7, 0x24, 0xac, 0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
    0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44, 0x29, 0xfc, 0x4d, 0x9a,
    0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70, 0x7c, 0x3e, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27,
    0xa3, 0x95, 0x74, 0x50, 0x1a, 0x53, 0x26, 0x83, 0x10, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c,
    0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3, 0x4f, 0x9e, 0x50, 0x3b,
    0xd8, 0x0c, 0x06, 0x22, 0xad, 0x79, 0xc6, 0xdc, 0xee, 0x88, 0x35, 0x47, 0xc6, 0xa3, 0xb3, 0x25,
};
const uint8_t signature[] = {
    0x6b, 0xc3, 0xa0, 0x66, 0x56, 0x84, 0x29, 0x30, 0xa2, 0x47, 0xe3, 0x0d, 0x58, 0x64, 0xb4, 0xd8,
    0x19, 0x23, 0x6b, 0xa7, 0xc6, 0x89, 0x65, 0x86, 0x2a, 0xd7, 0xdb, 0xc4, 0xe2, 0x4a, 0xf2, 0x8e,
    0x86, 0xbb, 0x53, 0x1f, 0x03, 0x35, 0x8b, 0xe5, 0xfb, 0x74, 0x77, 0x7c, 0x60, 0x86, 0xf8, 0x50,
    0xca, 0xef, 0x89, 0x3f, 0x0d, 0x6f, 0xcc, 0x2d, 0x0c, 0x91, 0xec, 0x01, 0x36, 0x93, 0xb4, 0xea,
    0x00, 0xb8, 0x0c, 0xd4, 0x9a, 0xac, 0x4e, 0xcb, 0x5f, 0x89, 0x11, 0xaf, 0xe5, 0x39, 0xad, 0xa4,
    0xa8, 0xf3, 0x82, 0x3d, 0x1d, 0x13, 0xe4, 0x72, 0xd1, 0x49, 0x05, 0x47, 0xc6, 0x59, 0xc7, 0x61,
    0x7f, 0x3d, 0x24, 0x08, 0x7d, 0xdb, 0x6f, 0x2b, 0x72, 0x09, 0x61, 0x67, 0xfc, 0x09, 0x7c, 0xab,
    0x18, 0xe9, 0xa4, 0x58, 0xfc, 0xb6, 0x34, 0xcd, 0xce, 0x8e, 0xe3, 0x58, 0x94, 0xc4, 0x84, 0xd7,
};
const uint8_t messageHash[] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

/**********Mocked Functions*********/
//Functions from CryptoAES.h
Crypto_AES::Crypto_AES(){}

Crypto_AES::~Crypto_AES(){}

uint8_t Crypto_AES::Intialize(uint8_t* AES128_Key, uint8_t KeySize, uint8_t* InitializationVector, uint8_t VectorSize)
{
    if (CRL_AES128_KEY != KeySize) {
        return 1;
    }

    if (CRL_AES_BLOCK != VectorSize) {
        return 2;
    }

    for (uint8_t i = 0; i < CRL_AES128_KEY; i++) {
        if (rsaDecryptedAESInformation[i] != AES128_Key[i]) {
            return 3;
        }
    }

    for (uint8_t i = 0; i < CRL_AES_BLOCK; i++) {
        if (rsaDecryptedAESInformation[i + CRL_AES128_KEY] != InitializationVector[i]) {
            return 4;
        }
    }

    return 0;
}

uint8_t Crypto_AES::Decrypt(uint8_t*  InputMessage,
                            uint16_t  InputMessageLength,
                            uint8_t*  OutputMessage,
                            uint16_t* OutputMessageLength)
{
    if ((0 == InputMessageLength) || (0 != InputMessageLength % CRL_AES128_KEY)) {
        return 1;
    }

    for (uint8_t i = 0; i < AES_ENCRYPTED_TESTMASSAGE_LENGTH; i++) {
        if (aesEncryptedTestMessage[i] != InputMessage[i]) {
            return 2;
        }
    }

    for (uint8_t i = 0; i < AES_DECRYPTED_TESTMASSAGE_LENGTH; i++) {
        OutputMessage[i] = aesDecryptedTestMessage[i];
    }
    *OutputMessageLength = AES_DECRYPTED_TESTMASSAGE_LENGTH;

    return 0;
}

uint8_t Crypto_AES::CloseDecryptionProcess(uint8_t* OutputMessage, uint32_t* OutputMessageLength)
{
    return 0;
}

//Functions from CryptoRSADecryption.h
Crypto_RSA_Decrypt::Crypto_RSA_Decrypt(){}

Crypto_RSA_Decrypt::~Crypto_RSA_Decrypt(){}

uint8_t Crypto_RSA_Decrypt::generateKeyPair(uint8_t* pubKey,
                                            uint8_t* pubKey_size,
                                            uint8_t* prvKey,
                                            uint8_t* prvKey_size,
                                            uint8_t* Modulus,
                                            uint8_t* Modulus_size)
{
    if ((NULL == pubKey) || (NULL == pubKey_size) || (NULL == prvKey) || (NULL == prvKey_size) || (NULL == Modulus) ||
        (NULL == Modulus_size)) {
        return 1;
    }

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        pubKey[i] = rsaDecryptPubKey[i];
    }
    *pubKey_size = (uint8_t)sizeof(rsaDecryptPubKey);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        prvKey[i] = rsaDecryptPrvKey[i];
    }
    *prvKey_size = (uint8_t)sizeof(rsaDecryptPubKey);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE; i++) {
        Modulus[i] = rsaDecryptModulus[i];
    }
    *Modulus_size = (uint8_t)sizeof(rsaDecryptModulus);

    return 0;
}

uint8_t Crypto_RSA_Decrypt::setPrivateKey(uint8_t* prvKey, uint8_t prvKey_size, uint8_t* Modulus, uint8_t Modulus_size)
{
    if (PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE != prvKey_size) {
        return 1;
    }

    if (PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE != Modulus_size) {
        return 2;
    }

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        if (rsaDecryptPrvKey[i] != prvKey[i]) {
            return 3;
        }
    }

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE; i++) {
        if (rsaDecryptModulus[i] != Modulus[i]) {
            return 4;
        }
    }

    return 0;
}

uint8_t Crypto_RSA_Decrypt::getDecryptedAESInformation(uint8_t* encryptedAESInformation,
                                                       int32_t  encryptedAESInformation_size,
                                                       uint8_t* decryptedAESInformation,
                                                       int32_t* decryptedAESInformation_size)
{
    if (PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE != encryptedAESInformation_size) {
        return 1;
    }

    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE; i++) {
        if (encryptedAESInformation[i] != rsaEncryptedAESInformation[i]) {
            return 2;
        }
    }

    for (uint8_t i = 0; i < (PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE); i++) {
        decryptedAESInformation[i] = rsaDecryptedAESInformation[i];
    }
    *decryptedAESInformation_size = (PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE);

    return 0;
}

//Functions from CryptoRSASignVerify.h
Crypto_RSA_Sign_Verify::Crypto_RSA_Sign_Verify(){}

Crypto_RSA_Sign_Verify::~Crypto_RSA_Sign_Verify(){}

uint8_t Crypto_RSA_Sign_Verify::SetPublicKey(uint8_t* T1_pubExp,
                                             uint8_t  T1_pubExp_size,
                                             uint8_t* T1_Modulus,
                                             uint8_t  T1_Modulus_size)
{
    if (PMD_CRYPTO_RSA_SIGN_EXP_SIZE != T1_pubExp_size) {
        return 1;
    }

    if (PMD_CRYPTO_RSA_SIGN_MOD_SIZE != T1_Modulus_size) {
        return 2;
    }

    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_SIGN_EXP_SIZE; i++) {
        if (rsaVerifySignPubKey[i] != T1_pubExp[i]) {
            return 3;
        }
    }

    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_SIGN_MOD_SIZE; i++) {
        if (rsaVerifySignModulus[i] != T1_Modulus[i]) {
            return 4;
        }
    }

    return 0;
}

uint8_t Crypto_RSA_Sign_Verify::SetSignedHash(uint8_t* ResultingHashValue, uint8_t ResultingHashValue_size)
{
    if (PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE != ResultingHashValue_size) {
        return 1;
    }

    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE; i++) {
        if (signature[i] != ResultingHashValue[i]) {
            return 2;
        }
    }

    return 0;
}

uint8_t Crypto_RSA_Sign_Verify::VerifyHash(uint8_t* SHA256_Hash, uint8_t SHA256_Hash_size)
{
    if (PMD_CRYPTO_RSA_SIGN_HASH_SIZE != SHA256_Hash_size) {
        return 1;
    }

    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_SIGN_HASH_SIZE; i++) {
        if (messageHash[i] != SHA256_Hash[i]) {
            return 2;
        }
    }

    return 0;
}

//Functions from CryptoSHA256.h
Crypto_SHA256::Crypto_SHA256(){}

Crypto_SHA256::~Crypto_SHA256(){}

uint8_t Crypto_SHA256::AppendString(uint8_t* InputMessage, uint32_t InputMessageLength)
{
    for (uint8_t i = 0; i < AES_DECRYPTED_TESTMASSAGE_LENGTH; i++) {
        if (aesDecryptedTestMessage[i] != InputMessage[i]) {
            return 5;
        }
    }

    return 0;
}

uint8_t Crypto_SHA256::GetHash(uint8_t* ResultingHashValue, int32_t* ResultingHashValueLength)
{
    for (uint8_t i = 0; i < PMD_CRYPTO_RSA_SIGN_HASH_SIZE; i++) {
        ResultingHashValue[i] = messageHash[i];
    }
    *ResultingHashValueLength = PMD_CRYPTO_RSA_SIGN_HASH_SIZE;

    return 0;
}

/**********Tests**********/
/*
 * @brief       This function checks if the Method StoreSignatur throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_DecryptByteStream()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x00 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptPrvKey, sizeof(rsaDecryptPrvKey), (uint8_t*)rsaDecryptModulus,
                                     sizeof(rsaDecryptModulus)));
    CHECK(0x00 == Crypto.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));
    CHECK(0x11 ==
          Crypto.DecryptByteStream(aesEncryptedTestMessage, 0, aesDecryptedOutputbuffer,
                                   (uint16_t*)&aesDecryptedOutput_size));
    CHECK(0x11 ==
          Crypto.DecryptByteStream(aesEncryptedTestMessage, (uint16_t)sizeof(aesEncryptedTestMessage) - 1,
                                   aesDecryptedOutputbuffer,
                                   (uint16_t*)&aesDecryptedOutput_size));
    CHECK(0x12 ==
          Crypto.DecryptByteStream((uint8_t*)aesDecryptedTestMessage, (uint16_t)sizeof(aesEncryptedTestMessage),
                                   aesDecryptedOutputbuffer,
                                   (uint16_t*)&aesDecryptedOutput_size));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Method StoreSignatur throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_StoreSignatur()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x11 == Crypto.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature) - 1));
    CHECK(0x12 == Crypto.StoreSignatur((uint8_t*)rsaVerifySignPubKey, (uint8_t)sizeof(signature)));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Method StoreRSAVerificationInformation throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_StoreRSAVerificationInformation()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x11 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey) - 1,
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x12 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus) - 1));
    CHECK(0x13 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x14 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignModulus)));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Method DecryptStoreAESInformation throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_DecryptStoreAESInformation()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x00 == Crypto.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x11 == Crypto.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation) - 1));
    CHECK(0x12 == Crypto.DecryptStoreAESInformation((uint8_t*)rsaDecryptPrvKey, sizeof(rsaEncryptedAESInformation)));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Method SetRSADecryptionkey throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_SetRSADecryptionkey()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x11 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptPrvKey, sizeof(rsaDecryptPrvKey) - 1,
                                     (uint8_t*)rsaDecryptModulus,
                                     sizeof(rsaDecryptModulus)));
    CHECK(0x12 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptPrvKey, sizeof(rsaDecryptPrvKey), (uint8_t*)rsaDecryptModulus,
                                     sizeof(rsaDecryptModulus) - 1));
    CHECK(0x13 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptModulus, sizeof(rsaDecryptPrvKey), (uint8_t*)rsaDecryptModulus,
                                     sizeof(rsaDecryptModulus)));
    CHECK(0x14 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptPrvKey, sizeof(rsaDecryptPrvKey), (uint8_t*)rsaDecryptPrvKey,
                                     sizeof(rsaDecryptModulus)));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Method GenerateRSAKeys throws the correct Error-Values,
 *                      if it's called with invalid Parameters
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidParameter_GenerateRSAKeys()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x11 == Crypto.GenerateRSAKeys(rsaPubKey, NULL, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x11 == Crypto.GenerateRSAKeys(NULL, NULL, NULL, NULL, NULL, NULL));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Class throws the correct Error-Values,
 *                      if the Methods are called in the wrong order
 *                      Error should be thrown if the AES decryption should be finished and there is no Signature stored,
 *                      no RSA-Verification-Key stored or there has no AES-decryption started.
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidFunctionCalls_FinishDecryption()
{
    TestCaseBegin();

    //Third Check - Error should be thrown if the AES decryption should be finished and there is no Signature stored.
    Cryptography Crypto_1;
    CHECK(0x00 == Crypto_1.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x00 ==
          Crypto_1.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                   (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x00 == Crypto_1.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));
    CHECK(0x00 ==
          Crypto_1.DecryptByteStream(aesEncryptedTestMessage, (uint16_t)sizeof(aesEncryptedTestMessage),
                                     aesDecryptedOutputbuffer,
                                     (uint16_t*)&aesDecryptedOutput_size));
    CHECK(0x01 == Crypto_1.FinishDecryption());

    //Forth Check - Error should be thrown if the AES decryption should be finished and there is no RSA-Verification-Key stored.
    Cryptography Crypto_2;
    CHECK(0x00 == Crypto_2.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x00 == Crypto_2.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));
    CHECK(0x00 == Crypto_2.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));
    CHECK(0x00 ==
          Crypto_2.DecryptByteStream(aesEncryptedTestMessage, (uint32_t)sizeof(aesEncryptedTestMessage),
                                     aesDecryptedOutputbuffer,
                                     &aesDecryptedOutput_size));
    CHECK(0x02 == Crypto_2.FinishDecryption());

    //Fifth Check - Error should be thrown if the AES decryption should be finished and there has no AES-decryption started.
    Cryptography Crypto_3;
    CHECK(0x00 == Crypto_3.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x00 ==
          Crypto_3.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                   (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x00 == Crypto_3.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));
    CHECK(0x00 == Crypto_3.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));
    CHECK(0x03 == Crypto_3.FinishDecryption());

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Class throws the correct Error-Values,
 *                      if the Methods are called in the wrong order
 *                      Error should be thrown if the AES decryption should be started and there is no AES-Key stored in the function.
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidFunctionCalls_DecryptByteStream()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x00 == Crypto.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));
    CHECK(0x00 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x00 == Crypto.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));
    CHECK(0x01 ==
          Crypto.DecryptByteStream(aesEncryptedTestMessage, (uint32_t)sizeof(aesEncryptedTestMessage),
                                   aesDecryptedOutputbuffer,
                                   &aesDecryptedOutput_size));

    TestCaseEnd();
}

/*
 * @brief       This function checks if the Class throws the correct Error-Values,
 *                      if the Methods are called in the wrong order.
 *                      Error should be thrown if the AES key should be decrypted and there is no RSA set.
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_Error_InvalidFunctionCalls_DecryptStoreAESInformation()
{
    TestCaseBegin();

    Cryptography Crypto;
    CHECK(0x00 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));
    CHECK(0x00 == Crypto.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));
    CHECK(0x01 == Crypto.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));

    TestCaseEnd();
}

/*
 * @brief       This function tests if the whole cryptographic process for binary decryption works correct
 *                      There are 2 types to initialize the RSA Decryption Method.
 *                      Here the initialization occurs with the generation of a new RSA-Key-Pair
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_RegularProcessGenerateKey()
{
    TestCaseBegin();

    Cryptography Crypto;

    //Check if the Key-generation works correctly
    CHECK(0x00 == Crypto.GenerateRSAKeys(rsaPubKey, &rsaPubKey_size, rsaPrvKey, &rsaPrvKey_size, rsaMod, &rsaMod_size));

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        CHECK(rsaDecryptPubKey[i] == rsaPubKey[i]);
    }

    CHECK(PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE == rsaPubKey_size);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        CHECK(rsaDecryptPrvKey[i] == rsaPrvKey[i]);
    }
    CHECK(PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE == rsaPrvKey_size);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE; i++) {
        CHECK(rsaDecryptModulus[i] == rsaMod[i]);
    }
    CHECK(PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE == rsaMod_size);

    //Check if the Decryption and Storage of the AES information works correctly
    CHECK(0x00 == Crypto.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));

    //Check if storing the RSA Public-key for Verifying works correctly
    CHECK(0x00 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));

    //Check if storing the signatur works correctly
    CHECK(0x00 == Crypto.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));

    //Check if the Decryption of an InputMessage works correctly
    CHECK(0x00 ==
          Crypto.DecryptByteStream(aesEncryptedTestMessage, (uint32_t)sizeof(aesEncryptedTestMessage),
                                   aesDecryptedOutputbuffer,
                                   &aesDecryptedOutput_size));
    CHECK(AES_DECRYPTED_TESTMASSAGE_LENGTH == aesDecryptedOutput_size);
    for (uint8_t i = 0; i < AES_DECRYPTED_TESTMASSAGE_LENGTH; i++) {
        CHECK(aesDecryptedTestMessage[i] == aesDecryptedOutputbuffer[i]);
    }

    //Check if the Finishing of the Process works correctly
    CHECK(0x00 == Crypto.FinishDecryption());

    TestCaseEnd();
}

/*
 * @brief       This function tests if the whole cryptographic process for binary decryption works correct
 *                      There are 2 types to initialize the RSA Decryption Method.
 *                      Here the initialization occurs with inserting an external stored private Key;
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_RegularProcessSetKey()
{
    TestCaseBegin();

    Cryptography Crypto;

    //Check if SetKey works correctly
    CHECK(0x00 ==
          Crypto.SetRSADecryptionkey((uint8_t*)rsaDecryptPrvKey, sizeof(rsaDecryptPrvKey), (uint8_t*)rsaDecryptModulus,
                                     sizeof(rsaDecryptModulus)));

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        CHECK(rsaDecryptPubKey[i] == rsaPubKey[i]);
    }

    CHECK(PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE == rsaPubKey_size);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE; i++) {
        CHECK(rsaDecryptPrvKey[i] == rsaPrvKey[i]);
    }
    CHECK(PMD_CRYPTO_RSA_DECRYPT_EXP_SIZE == rsaPrvKey_size);

    for (uint8_t i = 1; i < PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE; i++) {
        CHECK(rsaDecryptModulus[i] == rsaMod[i]);
    }
    CHECK(PMD_CRYPTO_RSA_DECRYPT_MOD_SIZE == rsaMod_size);

    //Check if the Decryption and Storage of the AES information works correctly
    CHECK(0x00 == Crypto.DecryptStoreAESInformation(rsaEncryptedAESInformation, sizeof(rsaEncryptedAESInformation)));

    //Check if storing the RSA Public-key for Verifying works correctly
    CHECK(0x00 ==
          Crypto.StoreRSAVerificationInformation((uint8_t*)rsaVerifySignPubKey, sizeof(rsaVerifySignPubKey),
                                                 (uint8_t*)rsaVerifySignModulus, sizeof(rsaVerifySignModulus)));

    //Check if storing the signatur works correctly
    CHECK(0x00 == Crypto.StoreSignatur((uint8_t*)signature, (uint8_t)sizeof(signature)));

    //Check if the Decryption of an InputMessage works correctly
    CHECK(0x00 ==
          Crypto.DecryptByteStream(aesEncryptedTestMessage, (uint32_t)sizeof(aesEncryptedTestMessage),
                                   aesDecryptedOutputbuffer,
                                   &aesDecryptedOutput_size));
    CHECK(AES_DECRYPTED_TESTMASSAGE_LENGTH == aesDecryptedOutput_size);
    for (uint8_t i = 0; i < AES_DECRYPTED_TESTMASSAGE_LENGTH; i++) {
        CHECK(aesDecryptedTestMessage[i] == aesDecryptedOutputbuffer[i]);
    }

    //Check if the Finishing of the Process works correctly
    CHECK(0x00 == Crypto.FinishDecryption());

    TestCaseEnd();
}

int main(int argc, const char* argv[])
{
    UnitTestMainBegin();

    RunTest(true, ut_Test_Error_InvalidParameter_DecryptByteStream);
    RunTest(true, ut_Test_Error_InvalidParameter_StoreSignatur);
    RunTest(true, ut_Test_Error_InvalidParameter_StoreRSAVerificationInformation);
    RunTest(true, ut_Test_Error_InvalidParameter_DecryptStoreAESInformation);
    RunTest(true, ut_Test_Error_InvalidParameter_SetRSADecryptionkey);
    RunTest(true, ut_Test_Error_InvalidParameter_GenerateRSAKeys);
    RunTest(true, ut_Test_Error_InvalidFunctionCalls_FinishDecryption);
    RunTest(true, ut_Test_Error_InvalidFunctionCalls_DecryptByteStream);
    RunTest(true, ut_Test_Error_InvalidFunctionCalls_DecryptStoreAESInformation);
    RunTest(true, ut_Test_RegularProcessGenerateKey);
    RunTest(true, ut_Test_RegularProcessSetKey);

    UnitTestMainEnd();
}
