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

#include "DeepSleepInterface.h"
#include "trace.h"

static const int __attribute__((unused)) g_DebugZones = ZONE_ERROR | ZONE_WARNING | ZONE_VERBOSE | ZONE_INFO;

using os::DeepSleepModule;

std::vector<DeepSleepModule*> os::DeepSleepModule::Modules;

DeepSleepModule::DeepSleepModule(void)
{
    Modules.emplace_back(this);
}

DeepSleepModule::~DeepSleepModule(void)
{
    for (auto it = Modules.begin(); it != Modules.end(); ++it) {
        if (*it == this) {
            Modules.erase(it);
            break;
        }
    }
}
