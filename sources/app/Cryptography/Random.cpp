/*
 * RANDOM.cpp
 *
 *  Created on: 12.08.2016
 *      Author: tobias
 */

#include <stdint.h>
#include "Random.h"

#ifndef PMD_CRYPTO_RNG
	#define PMD_CRYPTO_RNG
	#include "rng.h"
	#include "drbg.h"
#endif
#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif
#ifndef STM32F30X
	#define STM32F30X
#endif

RNGinitInput_stt RNGinit_st;
int32_t status = RNG_SUCCESS;

/* Structure that will keep the Random State */
RNGstate_stt RNGstate;

/* DRBG type */
#ifndef USE_HW_RNG
  int32_t DRBGtype = C_DRBG_AES128;
#else
  int32_t DRBGtype = C_HW_RNG;
#endif

Random::Random(uint8_t* entropy_data,uint8_t entropy_data_size, uint8_t* nonce, uint8_t nonce_size, uint8_t* personalization_String, uint8_t personalization_String_size) {
#ifndef PMD_CRYPTO_INIT
#define PMD_CRYPTO_INIT
	/* DeInitialize STM32 Cryptographic Library */
	Crypto_DeInit();
#endif
	status = initialize(entropy_data,entropy_data_size, nonce, nonce_size, personalization_String, personalization_String_size);
}

Random::~Random(){
#ifndef PMD_CRYPTO_INIT
#define PMD_CRYPTO_INIT
	/* DeInitialize STM32 Cryptographic Library */
	Crypto_DeInit();
#endif
	// TODO Auto-generated destructor stub
}

int32_t Random::getNextRandomNumber(uint8_t* RandomString, uint8_t RandomString_size){
	if(status == RNG_SUCCESS){
		status = RNGgenBytes(&RNGstate, NULL, RandomString, RandomString_size);
	}
	return status;
}

int32_t Random::initialize(uint8_t* entropy_data,uint8_t entropy_data_size, uint8_t* nonce, uint8_t nonce_size, uint8_t* personalization_String, uint8_t personalization_String_size){
	/* Set the values of EntropyData, Nonce, Personalization String and their sizes inside the RNGinit_st structure */
	RNGinit_st.pmEntropyData = entropy_data;
	RNGinit_st.mEntropyDataSize = entropy_data_size;
	RNGinit_st.pmNonce =  nonce;
	RNGinit_st.mNonceSize =  nonce_size;
	RNGinit_st.pmPersData = personalization_String;
	RNGinit_st.mPersDataSize = personalization_String_size;

	status = RNGinit(&RNGinit_st, DRBGtype,  &RNGstate);
	return status;
}

int32_t Random::getStatus(){
	return status;
}

