/*
 * CryptoSHA256.h
 *
 *  Created on: 27.08.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_

class Crypto_SHA256 {
public:
	Crypto_SHA256();
	virtual ~Crypto_SHA256();
	uint8_t appentString(uint8_t* InputMessage, uint32_t InputMessageLength);
	uint8_t GetHash(uint8_t *ResultingHashValue, int32_t* ResultingHashValueLength);
private:
	void initialize();
};



#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOSHA256_H_ */
