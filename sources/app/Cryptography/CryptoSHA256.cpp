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

uint32_t Crypto_SHA256_status;                          // Status der Funktion 1 => Initialized;  2 => Hashing-process started

SHA256ctx_stt Crypto_SHA256_shaSt;

Crypto_SHA256::Crypto_SHA256()
{
    Initialize();
}

Crypto_SHA256::~Crypto_SHA256()
{
    // TODO Auto-generated destructor stub
}

/*
 * @brief  Initializes the Hashing-status-struct
 * @param  None
 * @retval None
 */
void Crypto_SHA256::Initialize()
{
    Crypto_SHA256_shaSt.mTagSize = CRL_SHA256_SIZE; // Set the size of the desired hash digest */
    Crypto_SHA256_shaSt.mFlags = E_HASH_DEFAULT;    // Set flag field to default value
    Crypto_SHA256_status = 1;
}

/*
 * @brief  Append a string to the currently the current state of the hash-function.
 *                 If this function is called the first time after initializing the hash-function
 *                 the stored string for hashing is empty at the start of this function
 * @param  inputMessage:                pointer to input message to be hashed.
 * @param  inputMessage_size:	input data message length in byte.
 * @retval error status:                0 => SUCCESS
 *                                                              1 => Problem occurred while appending the input String
 *                                                              2 => Problem occurred while initializing the internal storage-object for
 *                                                                       Managing the state of the hash-function
 */
uint8_t Crypto_SHA256::AppendString(uint8_t* inputMessage, uint32_t inputMessage_size)
{
    if (1 == Crypto_SHA256_status) {
        /*this Function needs to be called the first time after initializing the storageobject*/
        if (HASH_SUCCESS != SHA256_Init(&Crypto_SHA256_shaSt)) {
            return 2;
        }
        Crypto_SHA256_status = 2;
    }

    if (HASH_SUCCESS != SHA256_Append(&Crypto_SHA256_shaSt, inputMessage, inputMessage_size)) {
        return 1;
    }

    return 0;
}

/*
 * @brief       This Function finish's the hashing-process and returns the resulting hash-value.
 *                      After finishing the hashing process the internal structure will be reinitialized.
 *                      So, after finishing the hashing-process and getting the result, a new hashing-process can be started.
 * @param       resultingHashValue:             the resulting hash-value will be inserted into this parameter.
 * @param       resultingHashValue_size:	returns the length of resulting hash-value
 * @retval      error status:                           0 => SUCCESS
 *                                                                              1 => Problem occurred while finishing
 *                                                                              2 => Starting the GetHashfunction without putting an input String into the hash-function
 */
uint8_t Crypto_SHA256::GetHash(uint8_t* resultingHashValue, int32_t* resultingHashValue_size)
{
    if (2 == Crypto_SHA256_status) {
        if (HASH_SUCCESS != SHA256_Finish(&Crypto_SHA256_shaSt, resultingHashValue, resultingHashValue_size)) {
            return 1;
        } else {
            Initialize();
            return 0;
        }
    } else {
        return 2;
    }
}
