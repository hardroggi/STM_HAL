/*
 * Cryptography.cpp
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */

#include "Cryptography.h"

#include "CryptoRSADecrypt.h"
#include "CryptoRSASignVerify.h"
#include "CryptoSHA256.h"
#include "CryptoAES.h"


#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

Crypto_RSA_Decrypt RSADecrypt;
Crypto_RSA_Sign_Verify RSAVerify;
Crypto_AES AES;
Crypto_SHA256 Hash;



Cryptography::Cryptography() {
	// TODO Auto-generated constructor stub

}

Cryptography::~Cryptography() {
	// TODO Auto-generated destructor stub
}

uint8_t Cryptography::Generate_RSA_Keys(uint8_t *RSA_PubKey, uint8_t RSA_PubKey_Size, uint8_t *RSA_PrvKey, uint8_t RSA_PrvKey_Size, uint8_t *RSA_Modulus, uint8_t RSA_Modulus_Size){
	//TODO

	return 0;
}

uint8_t Cryptography::SetRSA_Decryptionkey(uint8_t  *RSA_Key, uint8_t RSA_Key_Size){
	//TODO
	return 0;
}

uint8_t Cryptography::Decrypt_Store_AES_Information(uint8_t  *AES_Information, uint8_t AES_Information_Size){
	//TODO
	return 0;
}

uint8_t Cryptography::Store_Signatur(uint8_t *Signatur, uint16_t SignaturSize){
	int Errorstatus = RSAVerify.setSignedHash(Signatur,SignaturSize);
	if(0 == Errorstatus){
		return 0;
	} else {
		return (16*1) + Errorstatus;
	}
}

uint8_t Cryptography::DecryptByteStream(uint8_t* InputMessage, uint8_t InputMessageLength, uint8_t  *OutputMessage, uint32_t *OutputMessageLength){

	uint8_t Errorstatus = AES.Crypto_AES_decrypt(InputMessage, InputMessageLength, OutputMessage, OutputMessageLength);
	if(Errorstatus != 0){
		return (16*1) + Errorstatus;
	}

	Errorstatus = Hash.appentString(OutputMessage, *OutputMessageLength);
	if(Errorstatus != 0){
		return (16*2) + Errorstatus;
	} else {
		return 0;
	}
}

uint8_t Cryptography::FinishDecryption(){
	/* Buffer to store the output data */
	uint8_t OutputMessage[32];
	uint32_t OutputMessageLength = 0;
	int32_t OutputMessageHashLength = 0;
	uint8_t Errorstatus = 0;
	Errorstatus = AES.Crypto_AES_close_decryption_process(OutputMessage, &OutputMessageLength);
	if(0 != Errorstatus){
		return (16*1) + Errorstatus;
	}

	Errorstatus = Hash.GetHash((uint8_t *)OutputMessage, &OutputMessageHashLength);
	if(0 != Errorstatus){
		return (16*2) + Errorstatus;
	}

	Errorstatus = RSAVerify.verifyHash((uint8_t *)OutputMessage, OutputMessageHashLength);
	if(0 == Errorstatus){
		return 0;
	} else {
		if(1 == Errorstatus){
			return 1;
		}else {
			return (16*3) + Errorstatus;
		}
	}
}

