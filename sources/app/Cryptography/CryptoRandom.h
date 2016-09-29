/*
 * RANDOM.h
 *
 *  Created on: 12.08.2016
 *  Author: tobias
 */
#include <stdint.h>

#ifndef SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_
#define SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_

class Crypto_Random
{
public:
    Crypto_Random(uint8_t* entropyData,
                  uint8_t  entropyData_size,
                  uint8_t* nonce,
                  uint8_t  nonce_size,
                  uint8_t* personalizationString,
                  uint8_t  personalizationString_size);
    virtual ~Crypto_Random();
    int32_t GetNextRandomNumber(uint8_t* randomString, uint8_t randomString_size);
    int32_t Initialize(uint8_t* entropyData,
                       uint8_t  entropyData_size,
                       uint8_t* nonce,
                       uint8_t  nonce_size,
                       uint8_t* personalizationString,
                       uint8_t  personalizationString_size);
    int32_t GetStatus();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_ */
