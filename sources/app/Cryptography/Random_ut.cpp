/*
 * Random_ut.cpp
 *
 *  Created on: 12.08.2016
 *  Author: tobias
 */


#include "unittest.h"

#include <cmath>
#include <stdio.h>

#include "Random.h"
#ifndef PMD_CRYPTO_RNG
	#define PMD_CRYPTO_RNG
	#include "rng.h"
	#include "drbg.h"
#endif



/**********Mocked defines **********/
#define RNG_SUCCESS                  (int32_t) (0)    /*!<  RNG Success */
#define C_DRBG_AES128 0  /*!< Constant associated with the DRBG based on AES-128 to be used as DRBG for the random engine */
#define C_HW_RNG 1          /*!< Constant associated with the use of an HW TRNG for the random engine */
#define CRL_DRBG_AES128_STATE_SIZE         36u         /*!< Required size in bytes for a DRBG-AES128 state */


/**********Mocked Cryptofunctions**********/
void Crypto_DeInit(){
	/*
	 * Empty Function
	 * No initialization necessary
	 */
}

int32_t RNGinit(const RNGinitInput_stt *P_pInputData, int32_t P_DRBGtype, RNGstate_stt *P_pRandomState){
	return RNG_SUCCESS;
}

int32_t RNGgenBytes(RNGstate_stt *P_pRandomState, const RNGaddInput_stt *P_pAddInput, uint8_t *P_pOutput, int32_t P_OutLen){
	static int timesCalled =0;
	timesCalled++;
	for(int i=0; i<P_OutLen; i++){
		P_pOutput[i] = (timesCalled*i*i*7)%255;
	}
	return RNG_SUCCESS;
}

/**********Testdata**********/
uint8_t entropy_data[32] = {
                             0x9d, 0x20, 0x1a, 0x18, 0x9b, 0x6d, 0x1a, 0xa7, 0x0e,
                             0x79, 0x57, 0x6f, 0x36, 0xb6, 0xaa, 0x88, 0x55, 0xfd,
                             0x4a, 0x7f, 0x97, 0xe9, 0x71, 0x69, 0xb6, 0x60, 0x88,
                             0x78, 0xe1, 0x9c, 0x8b, 0xa5
                           };
/* Nonce. Non repeating sequence, such as a timestamp */
uint8_t nonce[] = {0xFE, 0xA9, 0x96, 0xD4, 0x62, 0xC5};
/* Personalization String */
uint8_t personalization_String[] = {0x1E, 0x6C, 0x7B, 0x82, 0xE5, 0xA5, 0x71, 0x8D};





/**********Tests**********/
/*
 * This method Tests only if the initialization of the Class is working correct
 */
int ut_Test_initialize(){
    TestCaseBegin();

	Random newRandom(entropy_data, sizeof(entropy_data), nonce, sizeof(nonce), personalization_String, sizeof(personalization_String));
    CHECK(RNG_SUCCESS == newRandom.getStatus());

    TestCaseEnd();
}
/*
 * This method Tests at first if the initialization of the Class is working correct.
 * Afterwards it tests if the generation of Random Numbers is working fine.
 */
int ut_Test_getNextRandomNumber(){
    TestCaseBegin();

    /*Initialize random number generator*/
	Random newRandom(entropy_data, sizeof(entropy_data), nonce, sizeof(nonce), personalization_String, sizeof(personalization_String));
    CHECK(newRandom.getStatus() == RNG_SUCCESS);

    uint8_t randomString[8]; //Array where the Random Number will be parsed in
    /*More Times Checking getNextRandomNumber to be sure that after each call a new number will be generated*/
    for(int j=1; j<8; j++){
		CHECK(RNG_SUCCESS == newRandom.getNextRandomNumber(randomString, sizeof(randomString)));
		for(int i=0; i<8; i++){
			int expectedValue = (j*i*i*7)%255;
			CHECK(expectedValue == randomString[i]);
		}
    }

    TestCaseEnd();
}

int main(int argc, const char* argv[])
{
    UnitTestMainBegin();

    RunTest(true, ut_Test_initialize);
    RunTest(true, ut_Test_getNextRandomNumber);

    UnitTestMainEnd();
}
