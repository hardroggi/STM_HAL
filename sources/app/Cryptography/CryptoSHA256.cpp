/*
 * CryptoSHA256.cpp
 *
 *  Created on: 27.08.2016
 *      Author: tobias
 *
 */

#include <stdint.h>
#include "CryptoSHA256.h"
#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

SHA256ctx_stt P_pSHA256ctx;
uint32_t Status; 							// Status der Funktion 1 => Initialized;  2 => Hashing-process started

Crypto_SHA256::Crypto_SHA256() {
	initialize();
}

Crypto_SHA256::~Crypto_SHA256() {
	// TODO Auto-generated destructor stub
}

/*
 * @brief Initializes the Hashing-status-struct
 * @param  None
 * @retval None
 */
void Crypto_SHA256::initialize()
{
	P_pSHA256ctx.mTagSize = CRL_SHA256_SIZE;// Set the size of the desired hash digest */
	P_pSHA256ctx.mFlags = E_HASH_DEFAULT; 	// Set flag field to default value
	Status=1;
}

/*
 * @brief  	Anppant a string to the currently the current state of the hashfunction.
 * 		 	If this function is called the first time after initializing the hashfunction
 * 		 	the stored string for hashing is empty at the start of this function
 * @param  InputMessage: pointer to input message to be hashed.
 * @param  InputMessageLength: input data message length in byte.
 * @retval error status: 	0 => SUCCESS
 * 							1 => Problem occurred while appending the input String
 * 							2 => Problem occurred while initializing the internal storageobject for
 * 								 Managing the state of the hashfunction
 */
uint8_t Crypto_SHA256::appentString(uint8_t* InputMessage, uint32_t InputMessageLength){
	if(1 == Status){
		/*this Function needs to be called the first time after initializing the storageobject*/
		if(HASH_SUCCESS != SHA256_Init(&P_pSHA256ctx)){
			return 2;
		}
		Status=2;
	}

	if(HASH_SUCCESS != SHA256_Append(&P_pSHA256ctx, InputMessage, InputMessageLength)){
		return 1;
	}
	return 0;
}

/*
 * @brief  	This Function finish's the hashing-process and returns the resulting hashvalue.
 * 			After finishing the hashing process the internal structure will be reinitialized.
 * 			So, after finishing the hashing-process and getting the result, a new hashing-process can be started.
 * @param  	MessageDigest: pointer to output parameter that will handle message digest
 * @param  	MessageDigestLength: pointer to output digest length.
 * @retval 	error status: 	0 => SUCCESS
 * 							1 => Problem occurred while finishing
 * 							2 => Starting the GetHashfunction without putting an input String into the hashfunction
 */
uint8_t Crypto_SHA256::GetHash(uint8_t *ResultingHashValue, int32_t* ResultingHashValueLength){
	if(2 == Status){
		if(HASH_SUCCESS != SHA256_Finish(&P_pSHA256ctx, ResultingHashValue, ResultingHashValueLength)){
			return 1;
		} else {
			initialize();
			return 0;
		}
	} else {
		return 2;
	}

}
