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
extern "C" {
#include "crypto.h"
}
#endif

uint8_t Crypto_AES_status;              //Defines the Status of the Function: 0 => Empty; 1 => Key and IV set; 2 => decryption started
uint8_t Crypto_AES_key[CRL_AES128_KEY]; //De/Encryption-Key (128 Bit)
uint8_t Crypto_AES_iv[CRL_AES_BLOCK];   //Initialization Vector for the first Block of the DecryptionProcess  (128 Bit)

AESCBCctx_stt Crypto_AES_aesCtx;        //Contains all Parameters for the DecryptionProcess

Crypto_AES::Crypto_AES()
{
#ifndef PMD_CRYPTO_INIT
#define PMD_CRYPTO_INIT
    /* DeInitialize STM32 Cryptographic Library */
    //Crypto_DeInit();
#endif
    Crypto_AES_status = 0;
}

Crypto_AES::~Crypto_AES()
{
    // TODO Auto-generated destructor stub
}

/**
 * @brief  Initialization Method for the AES Decryption Class
 * @param  aesKey:                                              pointer to the AES key to be used in the operation
 * @param  aesKey_size:					size of the AES key
 * @param  initializationVector:                pointer to the initialization vector (IV)
 * @param  initializationVector_size:	size of the initialization vector (IV)
 * @retval error status:                                0 => SUCCESS
 *                                                                              1 => Invalid InputSize of Parameter 1 "AES128_Key"				(Expected size is 16 Byte)
 *                                                                              2 => Invalid InputSize of Parameter 2 "InitializationVector"	(Expected size is 16 Byte)
 *                                                                              3 => DecryptionProcess already in execution Please finish the current Decryption first
 */
uint8_t Crypto_AES::Intialize(uint8_t* aesKey,
                              uint8_t  aesKey_size,
                              uint8_t* initializationVector,
                              uint8_t  initializationVector_size)
{
    /*Check if DecryptionProcess is already in execution */
    if (2 == Crypto_AES_status) {
        return 3;
    }

    /*Check if array-size of parameter AES128_Key is valid and copy content into Key-attribute*/
    if (CRL_AES128_KEY != aesKey_size) {
        return 1;
    } else {
        for (int i = 0; i < CRL_AES128_KEY; i++) {
            Crypto_AES_key[i] = aesKey[i];
        }
    }

    /*Check if array-size of parameter InitializationVector is valid and copy content into IV-attribute*/
    if (CRL_AES_BLOCK != initializationVector_size) {
        return 2;
    } else {
        for (int i = 0; i < CRL_AES_BLOCK; i++) {
            Crypto_AES_iv[i] = initializationVector[i];
        }
    }

    Crypto_AES_status = 1;
    //Initialization SUCCESSFULL
    return 0;
}

/**
 * @brief  Decrypts a not more than 16 Byte long (part of a) Message.
 * @param  inputMessage:                pointer to input message to be decrypted. (a multiple of 16 Byte long Array)
 * qparam  inputMessage_size:	input message length
 * @param  OutputMessage:               pointer to output parameter that will handle the decrypted message
 * @param  OutputMessageLength: pointer to decrypted message length.
 * @retval error status:                0 => SUCCESS
 *								1 => No key / IV set
 *								2 => Error occurred while initializing the AES-Cryptolibrary
 *								3 => Error occurred while decrypting the Message
 *								4 => Message is not a multiple of 16 Bytes long
 */
uint8_t Crypto_AES::Decrypt(uint8_t*  inputMessage,
                            uint16_t  inputMessage_size,
                            uint8_t*  outputMessage,
                            uint16_t* outputMessage_size)
{
    uint8_t temp_error = 0;

    /*Check if Key and IV are already set*/
    if (0 == Crypto_AES_status) {
        return 1;
    }

    /*Initialization of the Cryptolibrary at the first run of the method*/
    if (1 == Crypto_AES_status) {
        /* Initialize the decryption information container*/
        Crypto_AES_aesCtx.mFlags = E_SK_DEFAULT;            // Set flag field to default value */
        Crypto_AES_aesCtx.mKeySize = CRL_AES128_KEY;        // Set key size to 16 (corresponding to AES-128)
        Crypto_AES_aesCtx.mIvSize = CRL_AES_BLOCK;          // Set iv size field to IvLength

        /* Initialize the operation, by passing the key*/
        if (AES_SUCCESS != AES_CBC_Decrypt_Init(&Crypto_AES_aesCtx, Crypto_AES_key, Crypto_AES_iv)) {
            return 2;
        }

        Crypto_AES_status = 2;
    }

    /* Check if input Message is at least 16 Byte long and a multiple of 16*/
    if ((0 == inputMessage_size) || (0 != (inputMessage_size % CRL_AES128_KEY))) {
        return 4;
    }

    temp_error = AES_CBC_Decrypt_Append(&Crypto_AES_aesCtx,
                                        inputMessage,
                                        inputMessage_size,
                                        outputMessage,
                                        (int32_t*)outputMessage_size);
    if (AES_SUCCESS == temp_error) {
        return 0;
    } else {
        return 3;
    }
}

/**
 * @brief  Close the decryption process and puts the internal Status on value 1
 *                 After closing the process it is possible
 * @param  OutputMessage:               pointer to output parameter that will handle the decrypted message
 * @param  OutputMessageLength: pointer to decrypted message length.
 * @retval error status:                0 => SUCCESS
 *                                                              1 => Error occurred while closing the the decryption Process
 *                                                              2 => Closing the Process is impossible, because it wasn't even started
 */
uint8_t Crypto_AES::CloseDecryptionProcess(uint8_t* outputMessage, uint32_t* outputMessage_size)
{
    if (2 == Crypto_AES_status) {
        int32_t outputLength = 0;
        /* Do the Finalization */
        if (AES_SUCCESS ==
            AES_CBC_Decrypt_Finish(&Crypto_AES_aesCtx, (outputMessage + *outputMessage_size), &outputLength)) {
            /* Add data written to the information to be returned */
            *outputMessage_size += outputLength;

            Crypto_AES_status = 1;
            return 0;
        } else {
            return 1;
        }
    } else {
        return 2;
    }
}
