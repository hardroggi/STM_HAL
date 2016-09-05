/*
 * CryptoAES.h
 *
 *  Created on: 12.08.2016
 *  Author: Tobias Roggenhofer
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_

class Crypto_AES {
public:
	Crypto_AES();
	virtual ~Crypto_AES();
	uint8_t Crypto_AES_intialize(uint8_t  *AES128_Key, uint8_t KeySize,  uint8_t  *InitializationVector, uint8_t VectorSize);
	uint8_t Crypto_AES_decrypt(uint8_t* InputMessage, uint8_t InputMessageLength, uint8_t  *OutputMessage, uint32_t *OutputMessageLength);
	uint8_t Crypto_AES_close_decryption_process(uint8_t  *OutputMessage, uint32_t *OutputMessageLength);
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOAES_H_ */
