/*
 * CryptoAES.cpp
 *
 *  Created on: 12.08.2016
 *      Author: tobias
 */
#include <stdint.h>
#include "CryptoAES.h"
#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

#ifndef PMD_CRYPTO_AES
	#define PMD_CRYPTO_AES
	#include "aes.h"
	#include "aes_cbc.h"
#endif



uint8_t Status; 					//Defines the Status of the Function: 0 => Empty; 1 => Key and IV set; 2 => decryption started
uint8_t Key[CRL_AES128_KEY];		//De/Encryption-Key (128 Bit)
uint8_t IV[CRL_AES_BLOCK];			//Initialization Vector for the first Block of the DecryptionProcess  (128 Bit)
AESCBCctx_stt AESctx;				//Contains all Parameters for the DecryptionProcess


Crypto_AES::Crypto_AES() {
#ifndef PMD_CRYPTO_INIT
#define PMD_CRYPTO_INIT
	/* DeInitialize STM32 Cryptographic Library */
	Crypto_DeInit();
#endif
	Status=0;
}

Crypto_AES::~Crypto_AES() {
	// TODO Auto-generated destructor stub
}


/*
  * @brief  Initialization Method for the AES Decryption Class
  * @param  AES128_Key: pointer to the AES key to be used in the operation
  * @param  InitializationVector: pointer to the Initialization Vector (IV)
  * @retval error status: 	0 => SUCCESS
  * 						1 => Invalid InputSize of Parameter 1 "AES128_Key"				(Expected size is 16 Byte)
  * 						2 => Invalid InputSize of Parameter 2 "InitializationVector"	(Expected size is 16 Byte)
  * 						3 => DecryptionProcess already in execution Please finish the current Decryption first
 */
uint8_t Crypto_AES::Crypto_AES_intialize(uint8_t  *AES128_Key, uint8_t KeySize,  uint8_t  *InitializationVector, uint8_t VectorSize){

	/*Check if DecryptionProcess is already in execution */
	if(2 == Status){
		return 3;
	}

	//printf("Compare %d; internal Keysize:%d\n",CRL_AES128_KEY ,sizeof(InitializationVector));

	/*Check if array-size of parameter AES128_Key is valid and copy content into Key-attribute*/
	if(CRL_AES128_KEY != KeySize){
		return 1;
	} else {
		for(int i=0; i<CRL_AES128_KEY; i++){
			Key[i]=AES128_Key[i];
		}
	}

	/*Check if array-size of parameter InitializationVector is valid and copy content into IV-attribute*/
	if(CRL_AES_BLOCK != VectorSize){
		return 2;
	} else {
		for(int i=0; i<CRL_AES_BLOCK; i++){
			IV[i]=InitializationVector[i];
		}
	}

	Status=1;
	//Initialization SUCCESSFULL
	return 0;
}

/**
  * @brief  Decrypts a not more than 16 Byte long (part of a) Message.
  * @param  InputMessage: pointer to input message to be decrypted. (a multiple of 16 Byte long Array)
  * @param  OutputMessage: pointer to output parameter that will handle the decrypted message
  * @param  OutputMessageLength: pointer to decrypted message length.
  * @retval error status: 	0 => SUCCESS
  *							1 => No key / IV set
  *							2 => Error occurred while initializing the AES-Cryptolibrary
  *							3 => Error occurred while decrypting the Message
  *							4 => Message is not a multiple of 16 Bytes long
  */
uint8_t Crypto_AES::Crypto_AES_decrypt(uint8_t* InputMessage, uint8_t InputMessageLength, uint8_t  *OutputMessage, uint32_t *OutputMessageLength)
{
	/*Check if Key and IV are already set*/
	if(0 == Status){
		return 1;
	}

	/*Initialization of the Cryptolibrary at the first run of the method*/
	if(1 == Status){
		/* Initialize the decryption information container*/
		AESctx.mFlags = E_SK_DEFAULT;			// Set flag field to default value */
		AESctx.mKeySize = CRL_AES128_KEY;		// Set key size to 16 (corresponding to AES-128)
		AESctx.mIvSize = CRL_AES_BLOCK;			// Set iv size field to IvLength

		/* Initialize the operation, by passing the key*/
		if(AES_SUCCESS != AES_CBC_Decrypt_Init(&AESctx, Key, IV)){
			return 2;
		}

		Status=2;
	}

	/* Check if input Message is at least 16 Byte long and a multiple of 16*/
	if((0 == InputMessageLength) || (0 != InputMessageLength% CRL_AES128_KEY)){
		return 4;
	}

	/* Start decryptionProcess */
	int32_t outputLength = 0;

	if(AES_SUCCESS == AES_CBC_Decrypt_Append(&AESctx, InputMessage, sizeof(InputMessage), OutputMessage, &outputLength)){
		/* Write the number of data written*/
		*OutputMessageLength = outputLength;
		return 0;
	} else{
		return 3;
	}
}

/**
  * @brief  Close the decryption process and puts the internal Status on value 1
  * 		After closing the process it is possible
  * @param  OutputMessage: pointer to output parameter that will handle the decrypted message
  * @param  OutputMessageLength: pointer to decrypted message length.
  * @retval error status: 	0 => SUCCESS
  * 						1 => Error occurred while closing the the decryption Process
  * 						2 => Closing the Process is impossible, because it wasn't even started
  */
uint8_t Crypto_AES::Crypto_AES_close_decryption_process(uint8_t  *OutputMessage, uint32_t *OutputMessageLength){

	if(2 == Status){
		int32_t outputLength = 0;
		/* Do the Finalization */
		if(AES_SUCCESS == AES_CBC_Decrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength)){
			/* Add data written to the information to be returned */
			*OutputMessageLength += outputLength;

			Status=1;
			return 0;
		} else {
			return 1;
		}
	} else {
		return 2;
	}
}



