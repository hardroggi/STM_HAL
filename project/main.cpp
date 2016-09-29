/* Copyright (C) 2015  Nils Weiss
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/* GENERAL INCLUDES */
#include <string>

#include "os_Task.h"
#include "cpp_overrides.h"
#include "trace.h"

/* OS LAYER INCLUDES */
#include "hal_Factory.h"
#include "Gpio.h"
#include "Tim.h"
#include "TimHallDecoder.h"
#include "TimHallMeter.h"
#include "TimHalfBridge.h"
#include "TimPwm.h"
#include "Dma.h"
#include "Usart.h"
#include "UsartWithDma.h"
#include "Spi.h"
#include "SpiWithDma.h"
#include "Exti.h"
#include "Rtc.h"
#include "Adc.h"
#include "CRC.h"
#include "I2c.h"

/* DEV LAYER INLCUDES */
#include "TimSensorBldc.h"
#include "Battery.h"

/* APP LAYER INLCUDES */
#include "BatteryObserver.h"
#include "MotorController.h"

/* GLOBAL VARIABLES */
static const int __attribute__((used)) g_DebugZones = ZONE_ERROR | ZONE_WARNING | ZONE_VERBOSE | ZONE_INFO;
extern char _version_start;
extern char _version_end;
const std::string VERSION(&_version_start, (&_version_end - &_version_start));

/*CRYPTO*/
#include "CryptoRSADecrypt.h"
#include "CryptoRSASignVerify.h"
#include "CryptoSHA256.h"
#include "CryptoAES.h"
#define cplusplus
#ifndef PMD_CRYPTO_LIBRARY
#define PMD_CRYPTO_LIBRARY
extern "C" {
#include "crypto.h"
}
#endif

/***************************Test
   /**********Test data**********/
const uint8_t inputMessage[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/* string length only, without '\0' end of string marker */
uint32_t inputLength = (sizeof(inputMessage) - 1);
uint8_t messageDigest[CRL_SHA256_SIZE];
int32_t messageDigestLength = 0;
const uint8_t expectedOutputMessage[] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

void initializePowerSupply(void)
{
    constexpr auto& supply5V0 = hal::Factory<hal::Gpio>::get<hal::Gpio::ENABLE_5V0_SUPPLY>();
    constexpr auto& supply5V8 = hal::Factory<hal::Gpio>::get<hal::Gpio::ENABLE_5V8_SUPPLY>();

    supply5V0 = true;
    supply5V8 = true;
}

/*
   #define PLAINTEXT_LENGTH 64

   uint8_t outputMessageBuffer[PLAINTEXT_LENGTH];  // Buffer to store the output data
   uint32_t outputMessageBuffer_size = 0;			// Size of the output data

   const uint8_t plaintext[PLAINTEXT_LENGTH] =
   {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
   };

   // Key used for AES encryption/decryption
   uint8_t key[CRL_AES128_KEY] =
   {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5
   };

   // Initialization Vector
   uint8_t iv[CRL_AES_BLOCK] =
   {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
   };

   const uint8_t expectedCiphertext[PLAINTEXT_LENGTH] =
   {
    0xa3, 0x39, 0xe1, 0x37, 0xb7, 0xb6, 0x1f, 0xc5,
    0x32, 0xd9, 0x41, 0x59, 0x6a, 0xd8, 0x5b, 0x55,
    0xaa, 0x85, 0x16, 0x3a, 0x70, 0x5c, 0xa2, 0xea,
    0x95, 0x3f, 0xb2, 0x1d, 0x19, 0x9a, 0x6b, 0x25,
    0xb9, 0xa9, 0xb5, 0xd0, 0xd4, 0x37, 0x71, 0xf0,
    0x74, 0x5f, 0x2a, 0x00, 0x0f, 0xa9, 0x97, 0x5f,
    0x61, 0x4b, 0xa4, 0x6c, 0x1d, 0xe0, 0xa3, 0x24,
    0x4b, 0x69, 0xf3, 0x86, 0x13, 0x66, 0xf3, 0x3f
   };
 */

int main(void)
{
    //Crypto_SHA256 SHA256;
    //Crypto_AES Cryptography_aes;

    bool validate = true;
    int result = 0;
    hal::initFactory<hal::Factory<hal::Gpio> >();
    hal::initFactory<hal::Factory<hal::Tim> >();
    hal::initFactory<hal::Factory<hal::HallDecoder> >();
    hal::initFactory<hal::Factory<hal::HalfBridge> >();
    hal::initFactory<hal::Factory<hal::Pwm> >();
    hal::initFactory<hal::Factory<hal::Exti> >();
    hal::initFactory<hal::Factory<hal::Dma> >();
    hal::initFactory<hal::Factory<hal::Usart> >();
    hal::initFactory<hal::Factory<hal::UsartWithDma> >();
    hal::initFactory<hal::Factory<hal::Spi> >();
    hal::initFactory<hal::Factory<hal::SpiWithDma> >();
    hal::initFactory<hal::Factory<hal::Rtc> >();
    hal::initFactory<hal::Factory<hal::Adc> >();
    hal::initFactory<hal::Factory<hal::Crc> >();
    hal::initFactory<hal::Factory<hal::I2c> >();

    initializePowerSupply();

    TraceInit();
    Trace(ZONE_INFO, "Version: %c \r\n", &_version_start);

    os::ThisTask::sleep(std::chrono::milliseconds(10));

    /*
       /****AES TEST***** /
       if(0 != Cryptography_aes.Intialize(key, (uint16_t)sizeof(key), iv, (uint16_t)sizeof(iv))){
        validate =false;
       }
       if(0 != Cryptography_aes.Decrypt((uint8_t*)expectedCiphertext, (uint16_t)sizeof(expectedCiphertext), outputMessageBuffer, (uint16_t*)&outputMessageBuffer_size)){
        validate =false;
       }
       for(uint32_t i = 0; i < outputMessageBuffer_size; i++){
        if(outputMessageBuffer[i] != plaintext[i]){
            validate =false;
            break;
        }
       }
       if(0 == Cryptography_aes.CloseDecryptionProcess(outputMessageBuffer, &outputMessageBuffer_size)){
        validate =false;
       }

       /*****SHA TEST***** /
       if(0 != SHA256.AppendString((uint8_t*)inputMessage, inputLength)){
        validate =false;
       }
       if(0 != SHA256.GetHash((uint8_t*)messageDigest, &messageDigestLength)){
        validate =false;
       }
       for(int i = 0; i < messageDigestLength; i++){
        if(expectedOutputMessage[i] != messageDigest[i]){
            validate =false;
            break;
        }
       }
       if(validate){
        result = 1;
       } else {
        result = 2;
       }
     */

    os::Task::startScheduler();

    while (1) {}
}
