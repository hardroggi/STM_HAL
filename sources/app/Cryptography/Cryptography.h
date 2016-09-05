/*
 * Cryptography.h
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#ifndef SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_
#define SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_

class Cryptography {
public:
	Cryptography();
	virtual ~Cryptography();
	uint8_t Generate_RSA_Keys(uint8_t *RSA_PubKey, uint8_t RSA_PubKey_Size, uint8_t *RSA_PrvKey, uint8_t RSA_PrvKey_Size, uint8_t *RSA_Modulus, uint8_t RSA_Modulus_Size);
	uint8_t SetRSA_Decryptionkey(uint8_t  *RSA_Key, uint8_t RSA_Key_Size, uint8_t *RSA_Modulus, uint8_t RSA_Modulus_Size);
	uint8_t Decrypt_Store_AES_Information(uint8_t  *AES_Information, uint8_t AES_Information_Size);
	uint8_t Store_Signatur(uint8_t *Signatur, uint16_t SignaturSize);
	uint8_t DecryptByteStream(uint8_t* InputMessage, uint8_t InputMessageLength, uint8_t  *OutputMessage, uint32_t *OutputMessageLength);
	uint8_t FinishDecryption();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_CRYPTOGRAPHY_H_ */
