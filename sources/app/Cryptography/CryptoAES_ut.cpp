/*
 * CryptoAES_ut.cpp
 *
 *  Created on: 12.08.2016
 *      Author: tobias
 */
#include "unittest.h"

#include <stdint.h>
#include <cmath>
#include <stdio.h>

#include "CryptoAES.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif
#ifndef PMD_CRYPTO_AES
#define PMD_CRYPTO_AES
#include "aes.h"
#include "aes_cbc.h"
#endif

#define PLAINTEXT_LENGTH 64

uint8_t outputMessageBuffer[PLAINTEXT_LENGTH];  // Buffer to store the output data
uint32_t outputMessageBuffer_size = 0;          // Size of the output data

/**********Test data**********/
const uint8_t plaintext[PLAINTEXT_LENGTH] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

/* Key used for AES encryption/decryption */
uint8_t key[CRL_AES128_KEY] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5
};

/* Initialization Vector */
uint8_t iv[CRL_AES_BLOCK] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t expectedCiphertext[PLAINTEXT_LENGTH] = {
    0xa3, 0x39, 0xe1, 0x37, 0xb7, 0xb6, 0x1f, 0xc5,
    0x32, 0xd9, 0x41, 0x59, 0x6a, 0xd8, 0x5b, 0x55,
    0xaa, 0x85, 0x16, 0x3a, 0x70, 0x5c, 0xa2, 0xea,
    0x95, 0x3f, 0xb2, 0x1d, 0x19, 0x9a, 0x6b, 0x25,
    0xb9, 0xa9, 0xb5, 0xd0, 0xd4, 0x37, 0x71, 0xf0,
    0x74, 0x5f, 0x2a, 0x00, 0x0f, 0xa9, 0x97, 0x5f,
    0x61, 0x4b, 0xa4, 0x6c, 0x1d, 0xe0, 0xa3, 0x24,
    0x4b, 0x69, 0xf3, 0x86, 0x13, 0x66, 0xf3, 0x3f
};

/**********Mocked cryptography functions**********/
void Crypto_DeInit()
{
    /*
     * Empty Function
     * No initialization necessary
     */
}

int32_t AES_CBC_Decrypt_Init(AESCBCctx_stt* P_pAESCBCctx, const uint8_t* P_pKey, const uint8_t* P_pIv)
{
    return 0;
}

int32_t AES_CBC_Decrypt_Append(AESCBCctx_stt* P_pAESCBCctx,
                               const uint8_t* P_pInputBuffer,
                               int32_t        P_inputSize,
                               uint8_t*       P_pOutputBuffer,
                               int32_t*       P_pOutputSize)
{
    for (int i = 0; i < PLAINTEXT_LENGTH; i++) {
        P_pOutputBuffer[i] = plaintext[i];
    }
    *P_pOutputSize = (int32_t)PLAINTEXT_LENGTH;

    return 0;
}

int32_t AES_CBC_Decrypt_Finish(AESCBCctx_stt* P_pAESCBCctx, uint8_t* P_pOutputBuffer, int32_t* P_pOutputSize)
{
    return 0;
}

/**********Tests**********/
/**
 * @brief	Checks if a regular, single decryption works properly
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_regular_decryption()
{
    TestCaseBegin();

    Crypto_AES newAES;
    CHECK(0 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv)));
    CHECK(0 ==
          newAES.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext), outputMessageBuffer,
                         (uint16_t*)&outputMessageBuffer_size));
    for (uint32_t i = 0; i < outputMessageBuffer_size; i++) {
        CHECK(outputMessageBuffer[i] == plaintext[i]);
    }
    CHECK(0 == newAES.CloseDecryptionProcess(outputMessageBuffer, &outputMessageBuffer_size));

    TestCaseEnd();
}

/**
 * @brief       Checks if invalid Parameters/Calls in function initialize will return the expected error-messages
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_initialize_invalid_inputs()
{
    TestCaseBegin();

    Crypto_AES newAES;
    CHECK(1 == newAES.Intialize(key, sizeof(key) - 1, iv, sizeof(iv))); //invalid Input of Keysize
    CHECK(2 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv) + 1)); //invalid Input of IVsize

    CHECK(0 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv)));
    CHECK(0 ==
          newAES.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext), outputMessageBuffer,
                         (uint16_t*)&outputMessageBuffer_size));
    CHECK(3 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv)));     //Setting a new key after starting the decryption

    TestCaseEnd();
}

/**
 * @brief       Checks if invalid Parameters/Calls in function decrypt will return the expected error-messages
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_decrypt_invalid_inputs()
{
    TestCaseBegin();

    Crypto_AES newAES;
    CHECK(1 ==
          newAES.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext), outputMessageBuffer,
                         (uint16_t*)&outputMessageBuffer_size)); //Not Initialized

    CHECK(0 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv)));
    CHECK(4 ==
          newAES.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext) - 1, outputMessageBuffer,
                         (uint16_t*)&outputMessageBuffer_size));

    TestCaseEnd();
}

/**
 * @brief       Checks if invalid Calls in function close will return the expected error-messages
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_close_invalid_inputs()
{
    TestCaseBegin();

    Crypto_AES newAES;
    CHECK(2 == newAES.CloseDecryptionProcess(outputMessageBuffer, &outputMessageBuffer_size));
    CHECK(0 == newAES.Intialize(key, sizeof(key), iv, sizeof(iv)));
    CHECK(2 == newAES.CloseDecryptionProcess(outputMessageBuffer, &outputMessageBuffer_size));
    CHECK(0 ==
          newAES.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext), outputMessageBuffer,
                         (uint16_t*)&outputMessageBuffer_size));

    TestCaseEnd();
}

int main(int argc, const char* argv[])
{
    UnitTestMainBegin();

    RunTest(true, ut_Test_regular_decryption);
    RunTest(true, ut_Test_initialize_invalid_inputs);
    RunTest(true, ut_Test_decrypt_invalid_inputs);
    RunTest(true, ut_Test_close_invalid_inputs);

    UnitTestMainEnd();
}
