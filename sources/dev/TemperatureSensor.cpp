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

#include "TemperatureSensor.h"

constexpr std::tuple<const dev::TemperatureSensor_Internal,
                     const dev::TemperatureSensor_NTC,
                     const dev::TemperatureSensor_NTC,
                     const dev::TemperatureSensor_NTC> dev::Factory<dev::TemperatureSensor>::Container;
