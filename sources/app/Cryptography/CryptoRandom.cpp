/*
 * RANDOM.cpp
 *
 *  Created on: 12.08.2016
 *      Author: tobias
 */
#include <stdint.h>

#include "CryptoRandom.h"

#ifndef PMD_CRYPTO_RNG
#define PMD_CRYPTO_RNG
//#include "stm32f3xx_hal.h"
//#include "stm32f3xx_nucleo.h"
#endif
#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif
#ifndef STM32F30X
#define STM32F30X
#endif
/* DRBG type * /
   #ifndef USE_HW_RNG
   int32_t drbgType = C_DRBG_AES128;
   #else
   int32_t drbgType = C_HW_RNG;
   #endif
 */

int32_t Crypto_Random_status = RNG_SUCCESS;

RNGinitInput_stt Crypto_Random_rngInitSt;
RNGstate_stt Crypto_Random_rngState;        //Structure that will keep the Random State

Crypto_Random::Crypto_Random(uint8_t* entropyData,
                             uint8_t  entropyData_size,
                             uint8_t* nonce,
                             uint8_t  nonce_size,
                             uint8_t* personalizationString,
                             uint8_t  personalizationString_size)
{
    Crypto_Random_status = Initialize(entropyData,
                                      entropyData_size,
                                      nonce,
                                      nonce_size,
                                      personalizationString,
                                      personalizationString_size);
}

Crypto_Random::~Crypto_Random()
{
    // TODO Auto-generated destructor stub
}

int32_t Crypto_Random::GetNextRandomNumber(uint8_t* randomString, uint8_t randomString_size)
{
    if (Crypto_Random_status == RNG_SUCCESS) {
        Crypto_Random_status = RNGgenBytes(&Crypto_Random_rngState, NULL, randomString, randomString_size);
    }
    return Crypto_Random_status;
}

int32_t Crypto_Random::Initialize(uint8_t* entropyData,
                                  uint8_t  entropyData_size,
                                  uint8_t* nonce,
                                  uint8_t  nonce_size,
                                  uint8_t* personalizationString,
                                  uint8_t  personalizationString_size)
{
    /* Set the values of EntropyData, Nonce, Personalization String and their sizes inside the RNGinit_st structure */
    Crypto_Random_rngInitSt.pmEntropyData = entropyData;
    Crypto_Random_rngInitSt.mEntropyDataSize = entropyData_size;
    Crypto_Random_rngInitSt.pmNonce = nonce;
    Crypto_Random_rngInitSt.mNonceSize = nonce_size;
    Crypto_Random_rngInitSt.pmPersData = personalizationString;
    Crypto_Random_rngInitSt.mPersDataSize = personalizationString_size;

    Crypto_Random_status = RNGinit(&Crypto_Random_rngInitSt, &Crypto_Random_rngState);
    return Crypto_Random_status;
}

int32_t Crypto_Random::GetStatus()
{
    return Crypto_Random_status;
}
