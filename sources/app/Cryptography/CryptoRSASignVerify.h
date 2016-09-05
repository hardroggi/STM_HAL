/*
 * CryptoRSASign.h
 *
 *  Created on: 30.08.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_

class Crypto_RSA_Sign_Verify {
public:
	Crypto_RSA_Sign_Verify();
	uint8_t setPublicKey(uint8_t* T1_pubExp, uint8_t T1_pubExp_size, uint8_t* T1_Modulus, uint8_t T1_Modulus_size);
	uint8_t setSignedHash(uint8_t *ResultingHashValue, uint16_t ResultingHashValueLength);
	uint8_t verifyHash(uint8_t* SHA256_Hash, uint8_t SHA256_Hash_size);
	virtual ~Crypto_RSA_Sign_Verify();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTORSASIGNVERIFY_H_ */
