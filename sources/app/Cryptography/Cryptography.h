/*
 * Cryptography.h
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_

class Cryptography
{
public:
    Cryptography();
    virtual ~Cryptography();
    uint8_t GenerateRSAKeys(uint8_t* pubRSAEncryptionKey,
                            uint8_t* pubRSAEncryptionKey_size,
                            uint8_t* prvRSADecryptionKey,
                            uint8_t* prvRSADecryptionKey_size,
                            uint8_t* rsaModulus,
                            uint8_t* rsaModulus_size);
    uint8_t SetRSADecryptionkey(uint8_t* prvRSADecryptionKey,
                                uint8_t  prvRSADecryptionKey_size,
                                uint8_t* rsaModulus,
                                uint8_t  rsaModulus_size);
    uint8_t DecryptStoreAESInformation(uint8_t* encryptedAESInformation, uint8_t encryptedAESInformation_size);
    uint8_t StoreRSAVerificationInformation(uint8_t* pubRSAVerificationKey,
                                            uint8_t  pubRSAVerificationKey_size,
                                            uint8_t* rsaModulus,
                                            uint8_t  rsaModulus_size);
    uint8_t StoreSignatur(uint8_t* signatur, uint8_t signatur_size);
    uint8_t DecryptByteStream(uint8_t*  inputMessage,
                              uint16_t  inputMessage_size,
                              uint8_t*  outputMessage,
                              uint16_t* outputMessage_size);
    uint8_t FinishDecryption();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_ */
