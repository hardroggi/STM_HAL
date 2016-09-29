/*
 * CryptoSHA256_ut.cpp
 *
 *  Created on: 27.08.2016
 *      Author: tobias
 */
#include "unittest.h"

#include <stdint.h>
#include <cmath>
#include <stdio.h>

#include "CryptoSHA256.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif
#ifndef PMD_CRYPTO_HASH
#define PMD_CRYPTO_HASH
#include "hash.h"
#include "sha256.h"
#endif

uint8_t messageDigest[CRL_SHA256_SIZE];
int32_t messageDigestLength = 0;

/**********Test data**********/
const uint8_t inputMessage[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint32_t inputLength = (sizeof(inputMessage) - 1);                                      // string length only, without '\0' end of string marker

const uint8_t expectedOutputMessage[] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

/**********Mocked cryptography functions**********/
int32_t SHA256_Init(SHA256ctx_stt* P_pSHA256ctx)
{
    if (NULL != P_pSHA256ctx) {
        return HASH_SUCCESS;
    } else {
        return HASH_ERR_BAD_PARAMETER;
    }
}

int32_t SHA256_Append(SHA256ctx_stt* P_pSHA256ctx, const uint8_t* P_pInputBuffer, int32_t P_inputSize)
{
    if ((NULL == P_pSHA256ctx) || (NULL == P_pInputBuffer)) {
        return HASH_ERR_BAD_PARAMETER;
    } else {
        return HASH_SUCCESS;
    }
}

int32_t SHA256_Finish(SHA256ctx_stt* P_pSHA256ctx, uint8_t* P_pOutputBuffer, int32_t* P_pOutputSize)
{
    if ((NULL == P_pSHA256ctx) || (NULL == P_pOutputBuffer) || (NULL == P_pOutputSize)) {
        return HASH_ERR_BAD_PARAMETER;
    } else {
        for (uint8_t i = 0; i < CRL_SHA256_SIZE; i++) {
            P_pOutputBuffer[i] = expectedOutputMessage[i];
        }
        *P_pOutputSize = CRL_SHA256_SIZE;
        return HASH_SUCCESS;
    }
}

/**********Tests**********/
/*
 * @brief       Tests if the getHash function returns the correct errorcode on incorrect usage
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_getHash_Error()
{
    TestCaseBegin();

    Crypto_SHA256 SHA256;
    //Call getHash without filling the Hashfunction with a Message
    CHECK(2 == SHA256.GetHash((uint8_t*)messageDigest, &messageDigestLength));

    CHECK(0 == SHA256.AppendString((uint8_t*)inputMessage, inputLength));
    CHECK(1 == SHA256.GetHash(NULL, &messageDigestLength));

    TestCaseEnd();
}

/*
 * @brief       Tests if the appentString function returns the correct errorcode on incorrect usage
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_appentString_Error()
{
    TestCaseBegin();

    Crypto_SHA256 SHA256;
    CHECK(1 == SHA256.AppendString(NULL, inputLength));

    TestCaseEnd();
}

/*
 * @brief       Tests the regular hashing process twice
 * @param       None
 * @retval      Amount of errors
 */
int ut_Test_regular_Hash_process()
{
    TestCaseBegin();

    Crypto_SHA256 SHA256;

    /*Test the whole hashingproccess*/
    for (int i = 0; i < 10; i++) {
        CHECK(0 == SHA256.AppendString((uint8_t*)inputMessage, inputLength));
    }

    CHECK(0 == SHA256.GetHash((uint8_t*)messageDigest, &messageDigestLength));
    for (int i = 0; i < messageDigestLength; i++) {
        CHECK(messageDigest[i] == expectedOutputMessage[i]);
    }

    /*Test if the whole process works twice*/
    for (int i = 0; i < 10; i++) {
        CHECK(0 == SHA256.AppendString((uint8_t*)inputMessage, inputLength));
    }

    CHECK(0 == SHA256.GetHash((uint8_t*)messageDigest, &messageDigestLength));
    for (int i = 0; i < messageDigestLength; i++) {
        CHECK(messageDigest[i] == expectedOutputMessage[i]);
    }

    TestCaseEnd();
}

int main(int argc, const char* argv[])
{
    UnitTestMainBegin();

    RunTest(true, ut_Test_getHash_Error);
    RunTest(true, ut_Test_appentString_Error);
    RunTest(true, ut_Test_regular_Hash_process);

    UnitTestMainEnd();
}
