/*
 * CryptoAES.h
 *
 *  Created on: 12.08.2016
 *  Author: Tobias Roggenhofer
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_

class Crypto_AES
{
public:
    Crypto_AES();
    virtual ~Crypto_AES();
    uint8_t Intialize(uint8_t* aesKey,
                      uint8_t  aesKey_size,
                      uint8_t* initializationVector,
                      uint8_t  initializationVector_size);
    uint8_t Decrypt(uint8_t*  inputMessage,
                    uint16_t  inputMessage_size,
                    uint8_t*  outputMessage,
                    uint16_t* outputMessage_size);
    uint8_t CloseDecryptionProcess(uint8_t* outputMessage, uint32_t* outputMessage_size);
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_ */
