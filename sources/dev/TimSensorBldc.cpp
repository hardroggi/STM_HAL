/* Copyright (C) 2015  Nils Weiss, Alexander Strobl
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

#include <cmath>
#include "TimSensorBldc.h"
#include "trace.h"

static const int __attribute__((unused)) g_DebugZones = ZONE_ERROR | ZONE_WARNING | ZONE_VERBOSE | ZONE_INFO;

using dev::SensorBLDC;
using hal::HalfBridge;
using hal::HallDecoder;
using hal::Tim;

float SensorBLDC::getCurrentRPS(void) const
{
    const float maximumRPS = 70;

    const float rpsMean =
        (mHallDecoder.getCurrentRPS() + mHallMeter1.getCurrentRPS() + mHallMeter2.getCurrentRPS()) / 3;

    const float factorHighSpeedResolution = rpsMean / 100;
    const float factorLowSpeedResolution = (maximumRPS - rpsMean) / 100;

    const float rps =
        (mHallDecoder.getCurrentRPS() * factorLowSpeedResolution + mHallMeter1.getCurrentRPS() *
         factorHighSpeedResolution +
         mHallMeter2.getCurrentRPS() * factorHighSpeedResolution) / (
                                                                     factorHighSpeedResolution +
                                                                     factorHighSpeedResolution +
                                                                     factorLowSpeedResolution);

    if (mDirection == Direction::BACKWARD) {
        return 0.0 - rps;
    } else {
        return rps;
    }
}

float SensorBLDC::getCurrentOmega(void) const
{
#ifndef M_PI
    static constexpr float M_PI = 3.14159265358979323846f;
#endif

    return getCurrentRPS() * 2 * M_PI;
}

SensorBLDC::Direction SensorBLDC::getDirection(void) const
{
    return mDirection;
}

int32_t SensorBLDC::getPulsWidthPerMill(void) const
{
    return mHBridge.getPulsWidthPerMill();
}

void SensorBLDC::setPulsWidthInMill(int32_t value) const
{
    mHBridge.setPulsWidthPerMill(std::abs(value));
}

void SensorBLDC::setDirection(const Direction dir) const
{
    mDirection = dir;
}

void SensorBLDC::setMode(const Mode mode) const
{
    mMode = mode;
}

SensorBLDC::Mode SensorBLDC::getMode(void) const
{
    return mMode;
}

size_t SensorBLDC::getNextHallPosition(const size_t position) const
{
    if (mDirection == Direction::BACKWARD) {
        static const size_t positions[] = {0, 5, 3, 1, 6, 4, 2, 0};
        return positions[position];
    } else {
        static const size_t positions[] = {0, 3, 6, 2, 5, 1, 4, 0};
        return positions[position];
    }
}

size_t SensorBLDC::getPreviousHallPosition(const size_t position) const
{
    if (mDirection == Direction::FORWARD) {
        static const size_t positions[] = {0, 5, 3, 1, 6, 4, 2, 0};
        return positions[position];
    } else {
        static const size_t positions[] = {0, 3, 6, 2, 5, 1, 4, 0};
        return positions[position];
    }
}

void SensorBLDC::computeDirection(void) const
{
    const uint32_t currentPosition = mHallDecoder.getCurrentHallState();

    const bool directionChanged = currentPosition == getPreviousHallPosition(mLastHallPosition);

    if (directionChanged) {
//        if (mDirection == Direction::FORWARD) {
//            mDirection = Direction::BACKWARD;
//        } else {
//            mDirection = Direction::FORWARD;
//        }

        mHallDecoder.reset();
        mHallMeter1.reset();
        mHallMeter2.reset();
    }

    mLastHallPosition = currentPosition;
}

void SensorBLDC::commutate(const size_t hallPosition) const
{
    static bool manualCommutationActive = false;

    if ((manualCommutationActive == true) && (std::abs(mHallDecoder.getCurrentRPS()) > 15)) {
        manualCommutationActive = false;
        manualCommutation(hallPosition);
        mHBridge.enableTimerCommunication();
        prepareCommutation(hallPosition);
        return;
    }

    if ((manualCommutationActive == false) && (std::abs(mHallDecoder.getCurrentRPS()) < 10)) {
        mHBridge.disableTimerCommunication();
        manualCommutationActive = true;
        return;
    }

    if (manualCommutationActive == true) {
        manualCommutation(hallPosition);
    } else {
        prepareCommutation(hallPosition);
    }
}

void SensorBLDC::manualCommutation(const size_t hallPosition) const
{
    /*
     * 4Q Control
     *
     *  BRAKE      Q2| ACCELERATE Q1
     *  FORWARD      | FORWARD
     *  -------------+-------------
     *  ACCELERATE Q3| BRAKE      Q4
     *  BACKWARD     | BACKWARD
     *
     */

    static const std::array<std::array<const bool, 6>, 8> BLDC_BRIDGE_STATE_FORWARD_ACCELERATE = // Motor step
    {{
         // A AN  B BN  C CN
         { 0, 0, 0, 0, 0, 0 }, // V0
         { 0, 1, 0, 0, 1, 0 }, // V3
         { 0, 0, 1, 0, 0, 1 }, // V1
         { 0, 1, 1, 0, 0, 0 }, // V2
         { 1, 0, 0, 1, 0, 0 }, // V5
         { 0, 0, 0, 1, 1, 0 }, // V4
         { 1, 0, 0, 0, 0, 1 }, // V6
         { 0, 0, 0, 0, 0, 0 } // V0
     }};

    static const std::array<std::array<const bool, 6>, 8> BLDC_BRIDGE_STATE_BACKWARD_ACCELERATE = // Motor step
    {{
         // A AN  B BN  C CN
         { 0, 0, 0, 0, 0, 0 }, // V0
         { 0, 0, 1, 0, 0, 1 }, // V1
         { 1, 0, 0, 1, 0, 0 }, // V5
         { 1, 0, 0, 0, 0, 1 }, // V6
         { 0, 1, 0, 0, 1, 0 }, // V3
         { 0, 1, 1, 0, 0, 0 }, // V2
         { 0, 0, 0, 1, 1, 0 }, // V4
         { 0, 0, 0, 0, 0, 0 } // V0
     }};

    if ((mDirection == Direction::FORWARD)) {
        mHBridge.setBridge(BLDC_BRIDGE_STATE_FORWARD_ACCELERATE[hallPosition]);
    } else {
        mHBridge.setBridge(BLDC_BRIDGE_STATE_BACKWARD_ACCELERATE[hallPosition]);
    }
    mHBridge.triggerCommutationEvent();
}

void SensorBLDC::prepareCommutation(const size_t hallPosition) const
{
    /*
     * 4Q Control
     *
     *  BRAKE      Q2| ACCELERATE Q1
     *  FORWARD      | FORWARD
     *  -------------+-------------
     *  ACCELERATE Q3| BRAKE      Q4
     *  BACKWARD     | BACKWARD
     *
     */

    static const std::array<std::array<const bool, 6>, 8> BLDC_BRIDGE_STATE_ACCELERATE = // Motor step
    {{
         // A AN  B BN  C CN
         { 0, 0, 0, 0, 0, 0 }, // V0
         { 0, 1, 1, 0, 0, 0 }, // V2
         { 1, 0, 0, 0, 0, 1 }, // V6
         { 0, 0, 1, 0, 0, 1 }, // V1
         { 0, 0, 0, 1, 1, 0 }, // V4
         { 0, 1, 0, 0, 1, 0 }, // V3
         { 1, 0, 0, 1, 0, 0 }, // V5
         { 0, 0, 0, 0, 0, 0 } // V0
     }};

    mHBridge.setBridge(BLDC_BRIDGE_STATE_ACCELERATE[hallPosition]);
}

void SensorBLDC::checkMotor(const dev::Battery& battery) const
{
    const float minimalRPS = 0.5;
    const float maximalCurrent = 0.8;

    const bool motorBlocking =
        (std::abs(battery.getCurrent()) > maximalCurrent &&
         (std::abs(mHallDecoder.getCurrentRPS()) < minimalRPS));

    if (motorBlocking) {
        mLastHallPosition = getPreviousHallPosition(mHallDecoder.getCurrentHallState());
        prepareCommutation(mLastHallPosition);
        mHBridge.triggerCommutationEvent();
    }
}

void SensorBLDC::start(void) const
{
    mHallDecoder.registerCommutationCallback([this] {
                                                 commutate(mHallDecoder.getCurrentHallState());
                                             });

    mHallDecoder.registerHallEventCheckCallback([this] {
                                                    computeDirection();
                                                    return true;
                                                });

    mHallDecoder.mTim.enable();
    mHallMeter1.mTim.enable();
    mHallMeter2.mTim.enable();

    setPulsWidthInMill(0);

    mHBridge.enableOutput();
}

void SensorBLDC::stop(void) const
{
    mHBridge.disableOutput();

    mHallDecoder.mTim.disable();
    mHallMeter1.mTim.disable();
    mHallMeter2.mTim.disable();

    mHallDecoder.unregisterHallEventCheckCallback();
    mHallDecoder.unregisterCommutationCallback();
}

uint32_t SensorBLDC::getNumberOfPolePairs(void) const
{
    return mHallDecoder.POLE_PAIRS;
}

constexpr std::array<const dev::SensorBLDC,
                     dev::SensorBLDC::Description::__ENUM__SIZE> dev::Factory<dev::SensorBLDC>::Container;
