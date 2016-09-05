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

#include "TestLed.h"
#include "os_Task.h"
#include "cpp_overrides.h"
#include "trace.h"

/* OS LAYER INCLUDES */
#include "hal_Factory.h"
#include "Gpio.h"
#include "Tim.h"
#include "TimHallDecoder.h"
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
const std::string VERSION(&_version_start, ( &_version_end   -   & _version_start));

/*CRYPTO*/
#include "CryptoSHA256.h"

#ifndef PMD_CRYPTO_LIBRARY
	#define PMD_CRYPTO_LIBRARY
	#include "crypto.h"
#endif

#ifndef PMD_CRYPTO_HASH
	#define PMD_CRYPTO_HASH
	#include "hash.h"
	#include "sha256.h"
#endif

/**********Test data**********/
const uint8_t InputMessage[] =  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/* string length only, without '\0' end of string marker */
uint32_t InputLength = (sizeof(InputMessage) - 1);
uint8_t MessageDigest[CRL_SHA256_SIZE];
int32_t MessageDigestLength = 0;
const uint8_t Expected_OutputMessage[] =
  {
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

int main(void)
{
    hal::initFactory<hal::Factory<hal::Gpio> >();
    //hal::initFactory<hal::Factory<hal::Tim> >();
   // hal::initFactory<hal::Factory<hal::HallDecoder> >();
   // hal::initFactory<hal::Factory<hal::HalfBridge> >();
   // hal::initFactory<hal::Factory<hal::Pwm> >();
   // hal::initFactory<hal::Factory<hal::Exti> >();
   // hal::initFactory<hal::Factory<hal::Dma> >();
   // hal::initFactory<hal::Factory<hal::Usart> >();
   // hal::initFactory<hal::Factory<hal::UsartWithDma> >();
   // hal::initFactory<hal::Factory<hal::Spi> >();
   // hal::initFactory<hal::Factory<hal::SpiWithDma> >();
   // hal::initFactory<hal::Factory<hal::Rtc> >();
   // hal::initFactory<hal::Factory<hal::Adc> >();
   // hal::initFactory<hal::Factory<hal::Crc> >();
   // hal::initFactory<hal::Factory<hal::I2c> >();

    initializePowerSupply();


    Crypto_SHA256 SHA256;
	for(int i=0; i<10; i++){
		SHA256.appentString((uint8_t*)InputMessage, InputLength);
	}

    SHA256.GetHash((uint8_t*)MessageDigest, &MessageDigestLength);


    TraceInit();
    Trace(ZONE_INFO, "Version: %c \r\n", &_version_start);

    os::ThisTask::sleep(std::chrono::milliseconds(10));

    os::Task::startScheduler();

    while (1) {}
}
