/*
 * Cryptography.cpp
 *
 *  Created on: 01.09.2016
 *      Author: tobias
 */
#include <stdint.h>

#include "Cryptography.h"

#include "CryptoRSADecrypt.h"
#include "CryptoRSASignVerify.h"
#include "CryptoSHA256.h"
#include "CryptoAES.h"

#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
#include "crypto.h"
#endif

bool Cryptography_rsaDecryptionKeySet;
bool Cryptography_rsaVerificationKeySet;
bool Cryptography_signaturSet;
bool Cryptography_aesKeySet;
bool Cryptography_aesDecryptionStarted;

Crypto_RSA_Decrypt Cryptography_rsaDecrypt;
Crypto_RSA_Sign_Verify Cryptography_rsaVerify;
Crypto_AES Cryptography_aes;
Crypto_SHA256 Cryptography_hash;

Cryptography::Cryptography()
{
    Cryptography_rsaDecryptionKeySet = false;
    Cryptography_rsaVerificationKeySet = false;
    Cryptography_signaturSet = false;
    Cryptography_aesKeySet = false;
    Cryptography_aesDecryptionStarted = false;
}

Cryptography::~Cryptography()
{
    // TODO Auto-generated destructor stub
}

/**
 * @brief       This functions generates a new RSA-key-pair and stores the private key for decryption.
 *                      Afterwards the key-pair will be returned to the caller to store it for later usage.
 * @param       pubRSAEncryptionKey:		The public key, which will be returned after generation
 * @param       pubRSAEncryptionKey_size:	The size of the created public key
 * @param       prvRSADecryptionKey:		The private key, which will be returned after generation
 * @param       prvRSADecryptionKey_size:       The size of the created private key
 * @param       rsaModulus:	        Modulus for the RSA function, which will be returned after generation
 * @param       rsaModulus_size:	The size of the Modulus
 * @retval      error_code:             0x00 => SUCCESS
 *                                                              0x1? => Problem in Class Crypto_RSA_Decrypt function generateKeyPair occurred
 *                                                              //TODO implementation of the Class Crypto_RSA_Decrypt necessary
 */
uint8_t Cryptography::GenerateRSAKeys(uint8_t* pubRSAEncryptionKey,
                                      uint8_t* pubRSAEncryptionKey_size,
                                      uint8_t* prvRSADecryptionKey,
                                      uint8_t* prvRSADecryptionKey_size,
                                      uint8_t* rsaModulus,
                                      uint8_t* rsaModulus_size)
{
    int errorstatus = Cryptography_rsaDecrypt.generateKeyPair(pubRSAEncryptionKey,
                                                              pubRSAEncryptionKey_size,
                                                              prvRSADecryptionKey,
                                                              prvRSADecryptionKey_size,
                                                              rsaModulus,
                                                              rsaModulus_size);
    if (0 == errorstatus) {
        Cryptography_rsaDecryptionKeySet = true;
        return 0;
    } else {
        return (16 * 1) + errorstatus;
    }
}

/**
 * @brief       This functions stores the private key for the decryption of the AES-key
 * @param       prvRSADecryptionKey:		The public key, which will be stored for decryption
 * @param       prvRSADecryptionKey_size:       The size of the private key
 * @param       rsaModulus:	                                The Modulus, which will be stored for decryption
 * @param       rsaModulus_size:			The size of the Modulus
 * @retval      error_code:			                0x00 => SUCCESS
 *                                                                              0x1? => Problem in Class Crypto_RSA_Decrypt function setPrivateKey occurred
 *                                                                              0x11 => invalid RSA_Key_size (expected: 128 Byte)
 *                                                                              0x12 => invalid Modulus_size (expected: 128 Byte)
 *                                                                              0x1..	TODO implementation of the Class Crypto_RSA_Decrypt necessary
 */
uint8_t Cryptography::SetRSADecryptionkey(uint8_t* prvRSADecryptionKey,
                                          uint8_t  prvRSADecryptionKey_size,
                                          uint8_t* rsaModulus,
                                          uint8_t  rsaModulus_size)
{
    int errorstatus = Cryptography_rsaDecrypt.setPrivateKey(prvRSADecryptionKey,
                                                            prvRSADecryptionKey_size,
                                                            rsaModulus,
                                                            rsaModulus_size);
    if (0 == errorstatus) {
        Cryptography_rsaDecryptionKeySet = true;
        return 0;
    } else {
        return (16 * 1) + errorstatus;
    }
}

/**
 * @brief       This function decrypts the AES information (Key and IV) and stores it
 *                      After successfully storing this information it will be used to decrypt the binary
 * @param       encryptedAESInformation:		Encrypted AES information (Key and IV), which should be decrypted and stored.
 * @param       encryptedAESInformation_size:	The size of the Encrypted AES Information
 * @retval      error_code:                                     0x00 => SUCCESS
 *                                                                                      0x01 => there is no RSA key stored call SetRSADecryptionkey(set existing key) or
 *                                                                                                      GenerateRSAKeys(create new key) first
 *                                                                                      0x02 => The size of the decrypted AES-Information is invalid (expected 32 Byte)
 *                                                                                      0x1? => Problem in Class Crypto_RSA_Decrypt function getDecryptedAESInformation
 *                                                                                      0x1..	TODO implementation of the Class Crypto_RSA_Decrypt necessary
 *                                                                                      0x2? => Problem in Class Crypto_AES function Crypto_AES_intialize
 *                                                                                      0x21 => Invalid InputSize of Parameter AES128_Key"				(Expected size is 16 Byte)
 *                                                                              0x22 => Invalid InputSize of Parameter InitializationVector     (Expected size is 16 Byte)
 *                                                                              0x23 => DecryptionProcess already in execution Please finish the current Decryption first
 */
uint8_t Cryptography::DecryptStoreAESInformation(uint8_t* encryptedAESInformation, uint8_t encryptedAESInformation_size)
{
    if (!Cryptography_rsaDecryptionKeySet) {
        return 1;
    }

    int32_t aesInformation_size;
    uint8_t aesInformation[PMD_CRYPTO_RSA_DECRYPT_PACKAGE_SIZE];

    uint8_t errorstatus = Cryptography_rsaDecrypt.getDecryptedAESInformation(encryptedAESInformation,
                                                                             encryptedAESInformation_size,
                                                                             aesInformation,
                                                                             &aesInformation_size);
    if (0 != errorstatus) {
        return (16 * 1) + errorstatus;
    }

    //TODO The following part may change a little bit, because its not defined where in the AES Information stands in the unencrypted Packages.

    if (CRL_AES128_KEY + CRL_AES_BLOCK > aesInformation_size) {
        return 2;
    }

    errorstatus = Cryptography_aes.Intialize(aesInformation,
                                             CRL_AES128_KEY,
                                             (aesInformation + CRL_AES128_KEY),
                                             CRL_AES_BLOCK);
    if (0 == errorstatus) {
        Cryptography_aesKeySet = true;
        return 0;
    } else {
        return (16 * 2) + errorstatus;
    }
}

/**
 * @brief       This function stores the RSA verification information which is necessary to validate the signature of the binary
 * @param       pubRSAVerificationKey:		        The public key which will be use for verifying the signature
 * @param       pubRSAVerificationKey_size:     The size of the public key
 * @param       rsaModulus:	                                        Modulus which will be use for verifying the signature
 * @param       rsaModulus_size:				The size of the Modulus
 * @retval      error_code:                                     0x00 => SUCCESS
 *                                                                                      0x01 => there is no RSA key stored call SetRSADecryptionkey(set existing key) or
 *                                                                                                      GenerateRSAKeys(create new key) first
 *                                                                                      0x02 => The size of the decrypted AES-Information is invalid (expected 32 Byte)
 *                                                                                      0x1? => Problem in Class Crypto_RSA_Sign_Verify function setPublicKey
 *                                                                                      0x11 => Invalid Key size (expected value = 128)
 *                                                                              0x12 => Invalid modulus size (expected value = 128)
 */
uint8_t Cryptography::StoreRSAVerificationInformation(uint8_t* pubRSAVerificationKey,
                                                      uint8_t  pubRSAVerificationKey_size,
                                                      uint8_t* rsaModulus,
                                                      uint8_t  rsaModulus_size)
{
    int errorstatus = Cryptography_rsaVerify.SetPublicKey(pubRSAVerificationKey,
                                                          pubRSAVerificationKey_size,
                                                          rsaModulus,
                                                          rsaModulus_size);
    if (0 == errorstatus) {
        Cryptography_rsaVerificationKeySet = true;
        return 0;
    } else {
        return (16 * 1) + errorstatus;
    }
}

/**
 * @brief       This function stores the signature of the binary
 * @param       signatur:		        The signature of the binary which should be stored
 * @param       signatur_size:          The size of the signature
 * @retval      error_code:             0x00 => SUCCESS
 *                                                              0x1? => Problem in Class Crypto_RSA_Sign_Verify function setSignedHash
 *								0x01 => Invalid size of the signed Hash (expected value = 128)
 */
uint8_t Cryptography::StoreSignatur(uint8_t* signatur, uint8_t signatur_size)
{
    int errorstatus = Cryptography_rsaVerify.SetSignedHash(signatur, signatur_size);
    if (0 == errorstatus) {
        Cryptography_signaturSet = true;
        return 0;
    } else {
        return (16 * 1) + errorstatus;
    }
}

/**
 * @brief       This function decrypts the parts of the binary and returns it to the caller
 * @param       inputMessage:		Encrypted Part of the binary, which the function should decrypt
 * @param       inputMessage_size:      The size of the Encrypted Part (multiple of 16Byte)
 * @param       outputMessage:		Retunrs the decrypted Part of the binary
 * @param       outputMessage_size:     The size of the Decrypted Part
 * @retval      error_code:             0x00 => SUCCESS
 *								0x01 => There is no AES Key set
 *								0x1? => Problem in Class Crypto_AES function Crypto_AES_decrypt
 *								0x11 => No key / IV set
 *								0x12 => Error occurred while initializing the AES-Cryptolibrary
 *								0x13 => Error occurred while decrypting the Message
 *								0x14 => Message is not a multiple of 16 Bytes long
 *								0x2? => Problem in Class Crypto_SHA256 function appentString
 *								0x21 => Problem occurred while appending the input String
 *                                                              0x22 => Problem occurred while initializing the internal storageobject for
 *                                                                              Managing the state of the hashfunction
 */
uint8_t Cryptography::DecryptByteStream(uint8_t*  inputMessage,
                                        uint16_t  inputMessage_size,
                                        uint8_t*  outputMessage,
                                        uint16_t* outputMessage_size)
{
    if (!Cryptography_aesKeySet) {
        return 1;
    }

    uint8_t Errorstatus = Cryptography_aes.Decrypt(inputMessage, inputMessage_size, outputMessage, outputMessage_size);
    if (0 != Errorstatus) {
        return (16 * 1) + Errorstatus;
    }

    Errorstatus = Cryptography_hash.AppendString(outputMessage, *outputMessage_size);
    if (0 == Errorstatus) {
        Cryptography_aesDecryptionStarted = true;
        return 0;
    } else {
        return (16 * 2) + Errorstatus;
    }
}

/**
 * @brief       This function finish's the decryption of the binary and validates if the hash of the binary fits to the signatur
 * @retval      error_code:             0x00 => SUCCESS
 *								0x01 => There is no Signatur set
 *								0x02 => There is no Verification information set
 *								0x01 => The decryption of the binary has not started
 *								0x1? => Problem in Class Crypto_AES function Crypto_AES_close_decryption_process
 *                                                      0x11 => Error occurred while closing the the decryption Process
 *                                                      0x12 => Closing the Decryption-process is impossible, because it hasn't even started
 *								0x2? => Problem in Class Crypto_SHA256 function GetHash
 *                                                              0x21 => Problem occurred while finishing the Hashingprocess
 *                                                              0x22 => Starting the GetHashfunction without putting an input String into the hashfunction
 *                                                              0x3? => Problem in Class Crypto_RSA_Sign_Verify function verifyHash
 *								0x31 => "SUCCESS" SIGNATUR IS INVALID
 *                                                              0x32 => No Public RSAKey set
 *                                                              0x33 => No Signature set
 *                                                              0x34 => Invalid Hash-size
 *                                                              0x35 => Error occurred while verifying process
 */
uint8_t Cryptography::FinishDecryption()
{
    if (!Cryptography_signaturSet) {
        return 1;
    }

    if (!Cryptography_rsaVerificationKeySet) {
        return 2;
    }

    if (!Cryptography_aesDecryptionStarted) {
        return 3;
    }

    /* Buffer to store the output data */
    uint8_t outputMessage[32];
    uint32_t outputMessage_size = 0;
    int32_t outputMessageHash_size = 0;
    uint8_t errorstatus = 0;
    errorstatus = Cryptography_aes.CloseDecryptionProcess(outputMessage, &outputMessage_size);
    if (0 != errorstatus) {
        return (16 * 1) + errorstatus;
    }

    errorstatus = Cryptography_hash.GetHash((uint8_t*)outputMessage, &outputMessageHash_size);
    if (0 != errorstatus) {
        return (16 * 2) + errorstatus;
    }

    errorstatus = Cryptography_rsaVerify.VerifyHash((uint8_t*)outputMessage, outputMessageHash_size);
    if (0 == errorstatus) {
        return 0;
    } else {
        if (1 == errorstatus) {
            return 1;
        } else {
            return (16 * 3) + errorstatus;
        }
    }
}
