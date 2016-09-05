/*
 * CryptoRSASign.cpp
 *
 *  Created on: 30.08.2016
 *      Author: tobias
 */
#include <stdint.h>
#include "CryptoRSASignVerify.h"

#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

#ifndef PMD_CRYPTO_RSA_SIGN
	#define PMD_CRYPTO_RSA_SIGN
	#include "rsa.h"
#endif

#define PMD_CRYPTO_RSA_SIGN_EXP_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_MOD_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE 128
#define PMD_CRYPTO_RSA_SIGN_HASH_SIZE 32


uint8_t preallocated_buffer[4096]; 						// buffer required for internal allocation of memory

bool pubkSet;
RSApubKey_stt PubKey_st; 								// Structure that will contain the public key for verifying the signature
uint8_t pubExp[PMD_CRYPTO_RSA_SIGN_EXP_SIZE];			// Buffer that will contain the public Exponent
uint8_t pubMod[PMD_CRYPTO_RSA_SIGN_MOD_SIZE];			// Buffer that will contain the public Modulus
bool SignSet;
uint8_t Signature[PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE]; 	// Buffer that will contain the signature

Crypto_RSA_Sign_Verify::Crypto_RSA_Sign_Verify() {
#ifndef PMD_CRYPTO_INIT
#define PMD_CRYPTO_INIT
	/* DeInitialize STM32 Cryptographic Library */
	Crypto_DeInit();
#endif

	pubkSet = false;
	SignSet = false;
}

Crypto_RSA_Sign_Verify::~Crypto_RSA_Sign_Verify() {
	// TODO Auto-generated destructor stub
}

/**
 * @brief 	This functions stores the public exponent and the public Modulus in the class
 * @param  	T1_pubExp:		 The public exponent, which should be stored in the class
 * @param  	T1_pubExp_size:	 The size of the exponent
 * @param  	T1_Modulus:		 The public exponent, which should be stored in the class
 * @param  	T1_Modulus_size:
 * @retval 	error_code: 	0 => SUCCESS
 * 							1 => Invalid exponent size (expected value = 128)
 * 							2 => Invalid modulus size (expected value = 128)
 */
uint8_t Crypto_RSA_Sign_Verify::setPublicKey(uint8_t* T1_pubExp, uint8_t T1_pubExp_size, uint8_t* T1_Modulus, uint8_t T1_Modulus_size){
	if(PMD_CRYPTO_RSA_SIGN_EXP_SIZE != T1_pubExp_size){
		return 1;
	}

	if(PMD_CRYPTO_RSA_SIGN_MOD_SIZE != T1_Modulus_size){
		return 2;
	}
	PubKey_st.mExponentSize = T1_pubExp_size;
	PubKey_st.mModulusSize = T1_Modulus_size;

	for(int i=0; i<T1_pubExp_size; i++){
		pubExp[i] = T1_pubExp[i];
	}
	PubKey_st.pmExponent = pubExp;

	for(int i=0; i<T1_Modulus_size; i++){
		pubMod[i] = T1_Modulus[i];
	}
	PubKey_st.pmModulus = pubMod;

	pubkSet = true;
	return 0;
}

/**
 * @brief 	This functions stores the signed Hash in the class
 * @param  	ResultingHashValue:		 The public exponent, which should be stored in the class
 * @param  	ResultingHashValue_size: The size of the exponent
 * @retval 	error_code: 	0 => SUCCESS
 * 							1 => Invalid size of the signed Hash (expected value = 128)
 */
uint8_t Crypto_RSA_Sign_Verify::setSignedHash(uint8_t *ResultingHashValue, uint16_t ResultingHashValue_size){

	if(PMD_CRYPTO_RSA_SIGN_SIGNATUR_SIZE != ResultingHashValue_size){
		return 1;
	}
	for(int i=0; i<ResultingHashValue_size; i++){
		pubMod[i] = ResultingHashValue[i];
	}

	SignSet = true;

	return 0;
}

/**
 * @brief 	This functions stores the signed Hash in the class
 * @param  	SHA256_Hash:		The public exponent, which should be stored in the class
 * @param  	SHA256_Hash_size: 	The size of the exponent
 * @retval 	error_code: 	0 => SUCCESS SIGNATUR IS VALID
 * 							1 => "SUCCESS" SIGNATUR IS INVALID
 * 							2 => No Public Key set
 * 							3 => No Signature set
 * 							4 => Invalid Hash-size
 * 							5 => Error while verifying process
 */
uint8_t Crypto_RSA_Sign_Verify::verifyHash(uint8_t *SHA256_Hash, uint8_t SHA256_Hash_size){
	if(!pubkSet){
		return 2;
	}
	if(!SignSet){
		return 3;
	}
	if(PMD_CRYPTO_RSA_SIGN_HASH_SIZE != SHA256_Hash_size){
		return 4;
	}

	/* Initialize the membuf_st that must be passed to the RSA functions */
	membuf_stt mb_st;
	mb_st.mSize = sizeof(preallocated_buffer);
	mb_st.mUsed = 0;
	mb_st.pmBuf = preallocated_buffer;

	int32_t  status = RSA_PKCS1v15_Verify(&PubKey_st, SHA256_Hash, E_SHA256, Signature, &mb_st);
    if(SIGNATURE_VALID == status){
    	return 0;
    }else {
    	if(SIGNATURE_INVALID ==status){
    		return 1;
    	} else {
    		return 5;
    	}
    }
}
