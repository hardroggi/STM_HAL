/*
 * CryptoSHA256.h
 *
 *  Created on: 27.08.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_

class Crypto_SHA256
{
public:
    Crypto_SHA256();
    virtual ~Crypto_SHA256();
    uint8_t AppendString(uint8_t* inputMessage, uint32_t inputMessage_size);
    uint8_t GetHash(uint8_t* resultingHashValue, int32_t* resultingHashValue_size);
private:
    void Initialize();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_ */
