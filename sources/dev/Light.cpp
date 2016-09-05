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

#include <algorithm>
#include "Light.h"
#include "trace.h"

static const int __attribute__((unused)) g_DebugZones = ZONE_ERROR | ZONE_WARNING | ZONE_VERBOSE | ZONE_INFO;

using dev::Light;

std::array<std::array<uint8_t, Light::ARRAY_SIZE>, interface::Light::__ENUM__SIZE> Light::LedBitArrays;

uint8_t Light::getBitmask(const uint8_t in) const
{
    // Function returns bit code to create a high or low sequence for WS2812 with SPI
    // Waveform: |''|.. = High = 0xc = 0b1100
    // Waveform: |'|... = Low  = 0x8 = 0b1000
    switch (in & 0x03) {
    case 0:
        return 0x88;

    case 1:
        return 0x8c;

    case 2:
        return 0xc8;

    case 3:
        return 0xcc;
    }

    return 0;
}

void Light::convertByteToBitArray(const uint8_t byte, uint8_t* bitArray) const
{
    // Function has to fill the complete static variable LedBitArrays with the
    // corresponding bit codes for a specific color
    // pointer marks the current byte
    // each byte are 2 Bits for WS2812
    // a color contains 8 Bit (WS2812) -> 4 Byte in LedBitArrays
    // This function gets a color byte and converts each two bit from MSB to LSB
    // into 1 Byte for the LedBitArrays which is send over SPI later

    uint8_t bitmask = 0xc0;
    for (size_t i = 0; i < 8; i = i + 2) {
        // mask 2 Bits and shift to LSB and LSB+1
        uint8_t value = (byte & bitmask) >> (6 - i);
        // get Byte for 2 bits color code and assign value to LedBitArrays
        *bitArray = getBitmask(value);
        // prepare for next round
        bitArray++;
        bitmask = bitmask >> 2;
    }
}

void Light::displayNumber(const uint8_t number, const interface::Color& color) const
{
    uint8_t* pointer = LedBitArrays[mDescription].data();

    for (size_t i = 0; i < LED_COUNT; i++) {
        if (i < number) {
            convertByteToBitArray(color.green, pointer);
            pointer += 4;
            convertByteToBitArray(color.red, pointer);
            pointer += 4;
            convertByteToBitArray(color.blue, pointer);
            pointer += 4;
        } else {
            convertByteToBitArray(0, pointer);
            pointer += 4;
            convertByteToBitArray(0, pointer);
            pointer += 4;
            convertByteToBitArray(0, pointer);
            pointer += 4;
        }
    }

    mSpi.send(LedBitArrays[mDescription]);
}

void Light::setColor(const interface::Color& color) const
{
    displayNumber(LED_COUNT, color);
}

constexpr const std::array<const Light, interface::Light::Description::__ENUM__SIZE> dev::Factory<Light>::Container;
